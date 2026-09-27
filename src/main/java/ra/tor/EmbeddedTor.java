package ra.tor;

import ra.common.FileUtil;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Owns a real, local, self-managed Tor process - provisioned by {@link TorBinary}, spawned via
 * plain {@link ProcessBuilder}, driven entirely over its control port using this repo's own
 * {@link TORControlConnection} (no third-party control library, no Kotlin). This is the
 * <b>only</b> Tor this library ever talks to: there is no code path anywhere in this class, or
 * in {@link TORClientService}, that looks for or falls back to some other already-running Tor
 * instance - a system daemon, Orbot, anything else. If provisioning or bootstrap fails, {@link
 * #start} throws and the caller stays unavailable; it never proceeds on an unverified or
 * unbootstrapped process.
 *
 * <p>{@code __OwningControllerProcess} is set to this JVM's own pid, so Tor exits itself if
 * this process ever dies without a clean {@link #shutdown()} call - no orphaned background Tor
 * process ever survives this app.
 *
 * <p>{@link #start} does not return until Tor reports 100% bootstrap. A process that is merely
 * running but not yet bootstrapped has no real circuits, so returning earlier would let a
 * caller treat a non-functional SOCKS port as ready.
 *
 * <p>Not a substitute for independent security review - see DESIGN.md "Embedded Tor".
 */
public final class EmbeddedTor {

    private static final Logger LOG = Logger.getLogger(EmbeddedTor.class.getName());
    private static final Pattern BOOTSTRAP_PROGRESS = Pattern.compile("PROGRESS=(\\d+)");

    private final File dataDir;
    private volatile Process process;
    private volatile TORControlConnection control;
    private volatile int socksPort = -1;

    public EmbeddedTor(File dataDir) {
        this.dataDir = dataDir;
    }

    /** The authenticated control connection - only valid after {@link #start} returns successfully. */
    public TORControlConnection control() {
        return control;
    }

    /** The real port Tor's {@code SocksPort auto} bound to - only valid after {@link #start} returns successfully. */
    public int socksPort() {
        return socksPort;
    }

    public boolean isAlive() {
        Process p = process;
        return p != null && p.isAlive();
    }

    /**
     * Spawns and drives Tor to a fully bootstrapped, authenticated state. {@code bin} can come
     * from {@link TorBinary#resolve} (desktop: downloaded and verified into a local cache) or
     * be built directly via {@link TorBinary.Provisioned}'s public constructor by a caller that
     * obtained the binary its own way - e.g. Android, which packages it as {@code
     * jniLibs/<abi>/libtor.so} at APK-build time rather than downloading it at runtime (see
     * DESIGN.md "Android"). Either way, this method's own behavior - spawn, real cookie auth,
     * block until 100% bootstrap - is identical.
     */
    public void start(TorBinary.Provisioned bin, long timeoutMs) throws IOException {
        if (!dataDir.exists() && !dataDir.mkdirs()) {
            throw new IOException("could not create Tor data directory " + dataDir);
        }
        TorBinary.restrictToOwner(dataDir);

        File cookieFile = new File(dataDir, "control_auth_cookie");
        File controlPortFile = new File(dataDir, "control_port");
        File torrc = writeTorrc(bin, cookieFile, controlPortFile);

        List<String> cmd = new ArrayList<>();
        cmd.add(bin.torExecutable.getAbsolutePath());
        cmd.add("-f");
        cmd.add(torrc.getAbsolutePath());
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.environment().put("LD_LIBRARY_PATH", bin.libraryDir.getAbsolutePath());
        pb.environment().put("DYLD_LIBRARY_PATH", bin.libraryDir.getAbsolutePath());
        pb.directory(dataDir);
        pb.redirectErrorStream(true);
        LOG.info("Spawning embedded Tor: " + String.join(" ", cmd));
        process = pb.start();
        logProcessOutput(process);

        long deadline = System.currentTimeMillis() + timeoutMs;
        awaitFile(cookieFile, deadline);
        awaitFile(controlPortFile, deadline);

        int controlPort = readControlPort(controlPortFile);
        Socket socket = connectWithRetry(controlPort, deadline);
        TORControlConnection conn = new TORControlConnection(socket);
        byte[] cookie = FileUtil.readFile(cookieFile.getAbsolutePath());
        conn.authenticate(cookie);
        conn.takeOwnership();
        conn.setEvents(Collections.singletonList("STATUS_CLIENT"));
        this.control = conn;

        awaitBootstrapped(conn, deadline);

        String socksListener = conn.getInfo("net/listeners/socks");
        this.socksPort = parsePort(socksListener);
        LOG.info("Embedded Tor bootstrapped; SOCKS on 127.0.0.1:" + this.socksPort);
    }

    public void shutdown() {
        TORControlConnection c = control;
        if (c != null) {
            try {
                c.signal("SHUTDOWN");
            } catch (IOException ignored) {
                // best-effort - the process kill below is the real guarantee
            }
        }
        control = null;
        Process p = process;
        if (p != null) {
            try {
                if (!p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                    p.destroyForcibly();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                p.destroyForcibly();
            }
        }
        process = null;
        socksPort = -1;
    }

    private File writeTorrc(TorBinary.Provisioned bin, File cookieFile, File controlPortFile) throws IOException {
        File torrc = new File(dataDir, "torrc");
        StringBuilder sb = new StringBuilder();
        sb.append("DataDirectory ").append(dataDir.getAbsolutePath()).append('\n');
        sb.append("SocksPort auto\n");
        sb.append("ControlPort auto\n");
        sb.append("ControlPortWriteToFile ").append(controlPortFile.getAbsolutePath()).append('\n');
        sb.append("CookieAuthentication 1\n");
        sb.append("CookieAuthFile ").append(cookieFile.getAbsolutePath()).append('\n');
        Long pid = currentPidOrNull();
        if (pid != null) sb.append("__OwningControllerProcess ").append(pid).append('\n');
        sb.append("AvoidDiskWrites 1\n");
        sb.append("ClientOnly 1\n");
        sb.append("ExitRelay 0\n");
        if (bin.geoipFile.exists()) sb.append("GeoIPFile ").append(bin.geoipFile.getAbsolutePath()).append('\n');
        if (bin.geoip6File.exists()) sb.append("GeoIPv6File ").append(bin.geoip6File.getAbsolutePath()).append('\n');
        sb.append("Log notice stdout\n");
        try (FileWriter w = new FileWriter(torrc)) {
            w.write(sb.toString());
        }
        return torrc;
    }

    private static void awaitFile(File f, long deadline) throws IOException {
        while (!f.exists()) {
            if (System.currentTimeMillis() > deadline) {
                throw new IOException("timed out waiting for " + f.getName());
            }
            sleep(100);
        }
    }

    private static int readControlPort(File controlPortFile) throws IOException {
        // Tor writes a line like "PORT=127.0.0.1:9151\n" once ControlPort auto has bound.
        String content = new String(FileUtil.readFile(controlPortFile.getAbsolutePath()), StandardCharsets.UTF_8).trim();
        int idx = content.lastIndexOf(':');
        if (!content.startsWith("PORT=") || idx < 0) {
            throw new IOException("unrecognized control_port file contents: " + content);
        }
        return Integer.parseInt(content.substring(idx + 1));
    }

    private static int parsePort(String hostPort) throws IOException {
        // GETINFO net/listeners/socks answers e.g. "127.0.0.1:39251" (quoted per control-spec; already unquoted by getInfo()).
        if (hostPort == null) throw new IOException("Tor reported no SOCKS listener after bootstrap");
        String cleaned = hostPort.replace("\"", "").trim();
        int idx = cleaned.lastIndexOf(':');
        if (idx < 0) throw new IOException("unrecognized SOCKS listener: " + hostPort);
        return Integer.parseInt(cleaned.substring(idx + 1));
    }

    private static Socket connectWithRetry(int port, long deadline) throws IOException {
        IOException last = null;
        while (System.currentTimeMillis() <= deadline) {
            try {
                Socket s = new Socket();
                s.connect(new InetSocketAddress("127.0.0.1", port), 2000);
                return s;
            } catch (IOException e) {
                last = e;
                sleep(100);
            }
        }
        throw new IOException("could not connect to Tor's control port " + port, last);
    }

    private void awaitBootstrapped(TORControlConnection conn, long deadline) throws IOException {
        while (true) {
            String phase = conn.getInfo("status/bootstrap-phase");
            int progress = -1;
            if (phase != null) {
                Matcher m = BOOTSTRAP_PROGRESS.matcher(phase);
                if (m.find()) progress = Integer.parseInt(m.group(1));
            }
            if (progress >= 100) return;
            if (!isAlive()) {
                throw new IOException("tor process exited during bootstrap (last phase: " + phase + ")");
            }
            if (System.currentTimeMillis() > deadline) {
                throw new IOException("timed out waiting for Tor to bootstrap (last phase: " + phase + ")");
            }
            sleep(250);
        }
    }

    private void logProcessOutput(Process p) {
        Thread t = new Thread(() -> {
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    LOG.info("[embedded-tor] " + line);
                }
            } catch (IOException ignored) {
                // process ended - normal
            }
        }, "EmbeddedTor-Output");
        t.setDaemon(true);
        t.start();
    }

    /**
     * Java 8 target - no {@code ProcessHandle} (Java 9+); the JVM's PID is the numeric prefix
     * of the runtime MX bean's name ("pid@host"). {@code java.lang.management} is inconsistently
     * supported on Android's ART runtime (this class also runs there - see {@link
     * TorBinary}'s javadoc "Android"), so this degrades to omitting
     * {@code __OwningControllerProcess} entirely rather than failing the whole start - it's a
     * defense-in-depth self-cleanup guard, not something {@link #shutdown} depends on.
     */
    private static Long currentPidOrNull() {
        try {
            String name = ManagementFactory.getRuntimeMXBean().getName();
            int at = name.indexOf('@');
            return Long.parseLong(at > 0 ? name.substring(0, at) : name);
        } catch (RuntimeException e) {
            LOG.fine("could not determine this JVM's pid (" + e + ") - starting without __OwningControllerProcess");
            return null;
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}