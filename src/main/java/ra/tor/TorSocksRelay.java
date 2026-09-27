package ra.tor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

/**
 * A minimal local SOCKS5 CONNECT-only relay: a SOCKS5 <b>server</b> to whoever
 * connects to it (e.g. bitcoinj's {@code PeerGroup}), and a SOCKS5 <b>client</b>
 * to the real local Tor daemon underneath ({@link TORClientService#HOST}:
 * {@link TORClientService#PORT_SOCKS}) - a plain relay in between.
 *
 * <p>Exists so no consumer ever connects to the raw Tor daemon SOCKS port
 * directly - every connection this node makes over Tor passes through this
 * class's own code, which is what lets it observe real connection outcomes and
 * answer "is Tor egress actually working right now," not just "is the daemon
 * up" ({@link LocalTorDetector} only answers the latter). A daemon that is up
 * but whose outbound connections keep failing - e.g. a Tor exit relay's
 * {@code ExitPolicy} blocking a non-web port like Bitcoin's 8333 - is exactly
 * the gap this closes; see {@link #egressLikelyBlocked()}.
 *
 * <p>Loopback-only, no-auth SOCKS5 server; the only command it accepts from a
 * client is CONNECT (no BIND/UDP ASSOCIATE - nothing here needs them). IPv4
 * and domain-name address types are handled; IPv6 is rejected (unneeded so
 * far, kept out to keep this small).
 *
 * <p>Separately, {@link #resolve} lets a caller in the same process (e.g.
 * bitcoinj's DNS-seed peer discovery) resolve a hostname the same
 * never-touches-local-DNS way a CONNECT with a domain-name target already
 * does - by speaking Tor's own SOCKS5 {@code RESOLVE} extension directly to
 * the real upstream daemon, in this class's own client role rather than its
 * server role above.
 */
public final class TorSocksRelay {

    private static final Logger LOG = Logger.getLogger(TorSocksRelay.class.getName());

    private static final int SOCKS_VERSION = 0x05;
    private static final int CMD_CONNECT = 0x01;
    /** Tor's own SOCKS5 extension (see its {@code socks-extensions.txt}) - not part of the base RFC 1928 command set. */
    private static final int CMD_RESOLVE = 0xF0;
    private static final int ATYP_IPV4 = 0x01;
    private static final int ATYP_DOMAIN = 0x03;
    private static final int ATYP_IPV6 = 0x04;
    private static final int REP_SUCCEEDED = 0x00;
    private static final int REP_GENERAL_FAILURE = 0x01;
    private static final int REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08;

    /** How many of the most recent connection attempts to weigh when deciding {@link #egressLikelyBlocked()}. */
    private static final int OUTCOME_WINDOW = 10;
    /** {@code >=} this many of the last {@link #OUTCOME_WINDOW} attempts failing counts as "likely blocked." */
    private static final int BLOCKED_FAILURE_THRESHOLD = 8;
    private static final int UPSTREAM_CONNECT_TIMEOUT_MS = 20_000;

    private final int port;
    private final String upstreamHost;
    private final int upstreamPort;
    private final ExecutorService acceptExecutor =
            Executors.newSingleThreadExecutor(r -> new Thread(r, "TorSocksRelay-Accept"));
    private final ExecutorService connectionExecutor =
            Executors.newCachedThreadPool(r -> new Thread(r, "TorSocksRelay-Connection"));
    private final boolean[] recentOutcomes = new boolean[OUTCOME_WINDOW]; // true = success
    private final AtomicInteger outcomeCursor = new AtomicInteger();
    private final AtomicInteger outcomesRecorded = new AtomicInteger();

    private volatile ServerSocket serverSocket;

    /** Relays through {@code upstreamHost}:{@code upstreamPort} - {@link TORClientService} passes its embedded Tor process's own (dynamically-chosen) SOCKS port; tests point this at a fake upstream instead. */
    public TorSocksRelay(int port, String upstreamHost, int upstreamPort) {
        this.port = port;
        this.upstreamHost = upstreamHost;
        this.upstreamPort = upstreamPort;
    }

    /** Starts accepting connections; safe to call once. Throws if the port can't be bound. */
    public void start() throws IOException {
        serverSocket = new ServerSocket(port, 50, InetAddress.getByAddress(new byte[]{127, 0, 0, 1}));
        LOG.info("TorSocksRelay listening on 127.0.0.1:" + port);
        acceptExecutor.execute(this::acceptLoop);
    }

    public void shutdown() {
        ServerSocket ss = serverSocket;
        if (ss != null) {
            try { ss.close(); } catch (IOException ignored) { }
        }
        acceptExecutor.shutdownNow();
        connectionExecutor.shutdownNow();
    }

    /**
     * True once at least {@link #OUTCOME_WINDOW} attempts have been made and
     * {@link #BLOCKED_FAILURE_THRESHOLD} or more of the most recent ones failed.
     * Deliberately requires a full window before ever reporting true, so a
     * freshly-started relay with no history yet doesn't look blocked.
     */
    public boolean egressLikelyBlocked() {
        if (outcomesRecorded.get() < OUTCOME_WINDOW) return false;
        int failures = 0;
        synchronized (recentOutcomes) {
            for (boolean success : recentOutcomes) if (!success) failures++;
        }
        return failures >= BLOCKED_FAILURE_THRESHOLD;
    }

    private void recordOutcome(boolean success) {
        int i = Math.floorMod(outcomeCursor.getAndIncrement(), OUTCOME_WINDOW);
        synchronized (recentOutcomes) { recentOutcomes[i] = success; }
        outcomesRecorded.incrementAndGet();
    }

    /**
     * Resolves {@code hostname} to a single {@link InetAddress} using Tor's own SOCKS5
     * {@code RESOLVE} extension (command {@code 0xF0}) against the real upstream Tor daemon -
     * never the local/system DNS resolver, unlike {@link InetAddress#getAllByName}. Exists so a
     * caller that needs to look a hostname up (not connect to it) - e.g. bitcoinj's DNS-seed
     * peer discovery - can do so without leaking that lookup outside Tor. Returns exactly one
     * address per call: Tor's extension answers with a single resolved address, not a full
     * DNS A-record set, so a caller wanting several candidates should call this once per
     * hostname it already knows about (e.g. once per configured DNS seed) rather than expecting
     * one hostname to fan out into many.
     *
     * <p>The JDK's {@code Proxy}/{@code Socket} SOCKS support (used by {@link #handle} for
     * CONNECT) has no API for a non-CONNECT SOCKS5 command, so this method speaks the protocol
     * itself, in this class's client role rather than its server role. Counts toward {@link
     * #egressLikelyBlocked()} - see {@link #resolve(String, Duration, boolean)} for a variant
     * that doesn't.
     */
    public InetAddress resolve(String hostname, Duration timeout) throws IOException {
        return resolve(hostname, timeout, true);
    }

    /**
     * Same as {@link #resolve(String, Duration)}, but {@code trackOutcome=false} skips {@link
     * #recordOutcome} entirely - for a caller with a naturally high, expected failure rate (e.g.
     * Bitcoin DNS-seed lookups: not every seed answers, that says nothing about Tor's own health)
     * that would otherwise pollute {@link #egressLikelyBlocked()}'s shared rolling window.
     */
    public InetAddress resolve(String hostname, Duration timeout, boolean trackOutcome) throws IOException {
        byte[] nameBytes = hostname.getBytes(StandardCharsets.US_ASCII);
        if (nameBytes.length > 255) throw new IOException("hostname too long for SOCKS5: " + hostname);
        int timeoutMs = (int) Math.max(1, timeout.toMillis());
        try (Socket upstream = new Socket()) {
            upstream.connect(new InetSocketAddress(upstreamHost, upstreamPort), UPSTREAM_CONNECT_TIMEOUT_MS);
            upstream.setSoTimeout(timeoutMs);
            InputStream in = upstream.getInputStream();
            OutputStream out = upstream.getOutputStream();

            out.write(new byte[]{SOCKS_VERSION, 0x01, 0x00}); // 1 method offered: no-auth
            out.flush();
            int greetVer = readByte(in);
            int greetMethod = readByte(in);
            if (greetVer != SOCKS_VERSION || greetMethod != 0x00) {
                if (trackOutcome) recordOutcome(false);
                throw new IOException("upstream SOCKS5 greeting failed (ver=" + greetVer + " method=" + greetMethod + ")");
            }

            byte[] request = new byte[7 + nameBytes.length];
            request[0] = SOCKS_VERSION;
            request[1] = (byte) CMD_RESOLVE;
            request[2] = 0x00; // reserved
            request[3] = ATYP_DOMAIN;
            request[4] = (byte) nameBytes.length;
            System.arraycopy(nameBytes, 0, request, 5, nameBytes.length);
            // trailing 2-byte port is unused by RESOLVE - left as 0
            out.write(request);
            out.flush();

            int replyVer = readByte(in);
            int rep = readByte(in);
            readByte(in); // reserved
            int atyp = readByte(in);
            // Checked before interpreting atyp - a real finding: a failed RESOLVE (rep !=
            // REP_SUCCEEDED, e.g. the seed genuinely didn't answer) can carry atyp=0 (nothing to
            // report), which used to be misreported as "unsupported address type 0" instead of
            // the real, far more informative "RESOLVE failed, reply code N".
            if (replyVer != SOCKS_VERSION || rep != REP_SUCCEEDED) {
                if (trackOutcome) recordOutcome(false);
                throw new IOException("upstream RESOLVE of " + hostname + " failed, SOCKS5 reply code " + rep);
            }
            byte[] addr;
            switch (atyp) {
                case ATYP_IPV4: addr = new byte[4]; break;
                case ATYP_IPV6: addr = new byte[16]; break;
                default:
                    if (trackOutcome) recordOutcome(false);
                    throw new IOException("upstream RESOLVE reply had unsupported address type " + atyp);
            }
            readFully(in, addr);
            readByte(in); readByte(in); // BND.PORT - unused

            if (trackOutcome) recordOutcome(true);
            return InetAddress.getByAddress(hostname, addr);
        }
    }

    private void acceptLoop() {
        ServerSocket ss = serverSocket;
        while (ss != null && !ss.isClosed()) {
            try {
                Socket client = ss.accept();
                connectionExecutor.execute(() -> handle(client));
            } catch (IOException e) {
                if (!ss.isClosed()) LOG.fine("accept: " + e.getMessage());
            }
        }
    }

    private void handle(Socket client) {
        try (Socket c = client) {
            c.setSoTimeout(UPSTREAM_CONNECT_TIMEOUT_MS);
            InputStream in = c.getInputStream();
            OutputStream out = c.getOutputStream();

            if (!greet(in, out)) return;
            Target target = readConnectRequest(in, out);
            if (target == null) return;

            Socket upstream;
            try {
                upstream = new Socket(new Proxy(Proxy.Type.SOCKS,
                        new InetSocketAddress(upstreamHost, upstreamPort)));
                upstream.connect(InetSocketAddress.createUnresolved(target.host, target.port), UPSTREAM_CONNECT_TIMEOUT_MS);
            } catch (IOException e) {
                LOG.warning("upstream connect to " + target.host + ":" + target.port + " failed: " + e.getMessage());
                recordOutcome(false);
                reply(out, REP_GENERAL_FAILURE);
                return;
            }
            recordOutcome(true);
            try (Socket u = upstream) {
                reply(out, REP_SUCCEEDED);
                c.setSoTimeout(0);
                relay(c, u);
            }
        } catch (IOException e) {
            LOG.fine("connection: " + e.getMessage());
        }
    }

    /** SOCKS5 greeting: reads the method list, always selects no-auth (0x00) - a local, loopback-only relay needs none. */
    private boolean greet(InputStream in, OutputStream out) throws IOException {
        int ver = readByte(in);
        if (ver != SOCKS_VERSION) return false;
        int nMethods = readByte(in);
        readFully(in, new byte[nMethods]); // methods offered, ignored - we only ever pick no-auth
        out.write(new byte[]{SOCKS_VERSION, 0x00});
        out.flush();
        return true;
    }

    private static final class Target {
        final String host;
        final int port;
        Target(String host, int port) { this.host = host; this.port = port; }
    }

    /** Reads a CONNECT request; writes an error reply and returns null on anything else or a malformed request. */
    private Target readConnectRequest(InputStream in, OutputStream out) throws IOException {
        int ver = readByte(in);
        int cmd = readByte(in);
        readByte(in); // reserved
        int atyp = readByte(in);
        if (ver != SOCKS_VERSION || cmd != CMD_CONNECT) {
            reply(out, REP_GENERAL_FAILURE);
            return null;
        }
        String host;
        switch (atyp) {
            case ATYP_IPV4: {
                byte[] addr = new byte[4];
                readFully(in, addr);
                host = InetAddress.getByAddress(addr).getHostAddress();
                break;
            }
            case ATYP_DOMAIN: {
                int len = readByte(in);
                byte[] name = new byte[len];
                readFully(in, name);
                host = new String(name, java.nio.charset.StandardCharsets.US_ASCII);
                break;
            }
            case ATYP_IPV6:
            default:
                reply(out, REP_ADDRESS_TYPE_NOT_SUPPORTED);
                return null;
        }
        int port = (readByte(in) << 8) | readByte(in);
        return new Target(host, port);
    }

    /** {@code BND.ADDR}/{@code BND.PORT} are always reported as 0.0.0.0:0 - callers here never use them. */
    private void reply(OutputStream out, int rep) throws IOException {
        out.write(new byte[]{SOCKS_VERSION, (byte) rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0});
        out.flush();
    }

    /** Pumps bytes both directions until either side closes. */
    private void relay(Socket a, Socket b) throws IOException {
        Thread pump = new Thread(() -> pump(a, b), "TorSocksRelay-Pump");
        pump.setDaemon(true);
        pump.start();
        pump(b, a);
        try { pump.join(1000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
    }

    private static void pump(Socket from, Socket to) {
        try {
            InputStream in = from.getInputStream();
            OutputStream out = to.getOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                out.flush();
            }
        } catch (IOException ignored) {
            // either side closed - normal end of a relayed connection
        } finally {
            try { to.shutdownOutput(); } catch (IOException ignored) { }
        }
    }

    private static int readByte(InputStream in) throws IOException {
        int b = in.read();
        if (b < 0) throw new IOException("unexpected end of stream");
        return b;
    }

    private static void readFully(InputStream in, byte[] buf) throws IOException {
        int off = 0;
        while (off < buf.length) {
            int n = in.read(buf, off, buf.length - off);
            if (n < 0) throw new IOException("unexpected end of stream");
            off += n;
        }
    }
}
