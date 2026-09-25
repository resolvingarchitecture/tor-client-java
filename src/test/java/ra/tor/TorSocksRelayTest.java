package ra.tor;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Exercises {@link TorSocksRelay} against a fake upstream SOCKS5 server (standing
 * in for the real local Tor daemon) and a fake target server (standing in for
 * whatever the caller - e.g. bitcoinj - actually wants to reach) - no live Tor
 * daemon needed.
 */
class TorSocksRelayTest {

    private TorSocksRelay relay;
    private FakeUpstreamSocks upstream;
    private EchoServer target;

    @AfterEach
    void tearDown() {
        if (relay != null) relay.shutdown();
        if (upstream != null) upstream.shutdown();
        if (target != null) target.shutdown();
    }

    @Test
    void relaysASuccessfulConnectionAndEchoesBytes() throws Exception {
        target = new EchoServer();
        target.start();
        upstream = new FakeUpstreamSocks(true);
        upstream.start();
        int relayPort = freePort();
        relay = new TorSocksRelay(relayPort, "127.0.0.1", upstream.port());
        relay.start();

        byte[] reply = connectThroughRelayAndExchange(relayPort, "127.0.0.1", target.port(), "hello".getBytes(StandardCharsets.US_ASCII));
        assertArrayEquals("hello".getBytes(StandardCharsets.US_ASCII), reply);
        assertFalse(relay.egressLikelyBlocked(), "one success should not report blocked");
    }

    @Test
    void egressLikelyBlockedFlipsAfterRepeatedFailures() throws Exception {
        upstream = new FakeUpstreamSocks(false); // always fails the CONNECT
        upstream.start();
        int relayPort = freePort();
        relay = new TorSocksRelay(relayPort, "127.0.0.1", upstream.port());
        relay.start();

        for (int i = 0; i < 10; i++) {
            try {
                connectThroughRelayAndExchange(relayPort, "127.0.0.1", 1, new byte[0]);
            } catch (IOException ignored) {
                // expected - the relay reports the failure back over its own SOCKS server side
            }
        }
        assertTrue(relay.egressLikelyBlocked(), "10/10 failed attempts should report likely blocked");
    }

    /** Connects to the relay listening on {@code relayPort} as a SOCKS5 client, asks it to CONNECT to {@code host:port}, writes {@code payload}, and returns whatever comes back. */
    private static byte[] connectThroughRelayAndExchange(int relayPort, String host, int port, byte[] payload) throws IOException {
        Socket s = new Socket(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", relayPort)));
        s.connect(new InetSocketAddress(host, port), 5000);
        s.setSoTimeout(2000);
        try {
            OutputStream out = s.getOutputStream();
            InputStream in = s.getInputStream();
            if (payload.length > 0) {
                out.write(payload);
                out.flush();
                byte[] buf = new byte[payload.length];
                int off = 0;
                while (off < buf.length) {
                    int n = in.read(buf, off, buf.length - off);
                    if (n < 0) throw new IOException("closed before echo completed");
                    off += n;
                }
                return buf;
            }
            return new byte[0];
        } finally {
            s.close();
        }
    }

    private static int freePort() throws IOException {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        }
    }

    /** Echoes back whatever it reads, byte for byte. */
    private static final class EchoServer {
        private ServerSocket server;
        private final Thread thread = new Thread(this::run, "EchoServer");

        void start() throws IOException {
            server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            thread.setDaemon(true);
            thread.start();
        }

        int port() { return server.getLocalPort(); }

        void shutdown() {
            try { server.close(); } catch (IOException ignored) { }
        }

        private void run() {
            while (!server.isClosed()) {
                try (Socket c = server.accept()) {
                    InputStream in = c.getInputStream();
                    OutputStream out = c.getOutputStream();
                    byte[] buf = new byte[4096];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        out.write(buf, 0, n);
                        out.flush();
                    }
                } catch (IOException ignored) {
                    // closed - stop accepting
                }
            }
        }
    }

    /** A minimal SOCKS5 server: greets, reads a CONNECT request, then either relays to the real target (succeed=true) or always replies with a general-failure code (succeed=false). */
    private static final class FakeUpstreamSocks {
        private final boolean succeed;
        private ServerSocket server;
        private final AtomicBoolean running = new AtomicBoolean(true);
        private final Thread thread = new Thread(this::run, "FakeUpstreamSocks");

        FakeUpstreamSocks(boolean succeed) {
            this.succeed = succeed;
        }

        void start() throws IOException {
            server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            thread.setDaemon(true);
            thread.start();
        }

        int port() { return server.getLocalPort(); }

        void shutdown() {
            running.set(false);
            try { server.close(); } catch (IOException ignored) { }
        }

        private void run() {
            while (running.get() && !server.isClosed()) {
                try {
                    Socket c = server.accept();
                    new Thread(() -> handle(c), "FakeUpstreamSocks-Conn").start();
                } catch (IOException ignored) {
                    // closed - stop accepting
                }
            }
        }

        private void handle(Socket c) {
            try (Socket socket = c) {
                InputStream in = socket.getInputStream();
                OutputStream out = socket.getOutputStream();

                int ver = in.read();
                int nMethods = in.read();
                for (int i = 0; i < nMethods; i++) in.read();
                if (ver != 0x05) return;
                out.write(new byte[]{0x05, 0x00});
                out.flush();

                in.read(); // ver
                in.read(); // cmd
                in.read(); // rsv
                int atyp = in.read();
                String host;
                if (atyp == 0x01) {
                    byte[] addr = new byte[4];
                    readFully(in, addr);
                    host = InetAddress.getByAddress(addr).getHostAddress();
                } else if (atyp == 0x03) {
                    int len = in.read();
                    byte[] name = new byte[len];
                    readFully(in, name);
                    host = new String(name, StandardCharsets.US_ASCII);
                } else {
                    return;
                }
                int port = (in.read() << 8) | in.read();

                if (!succeed) {
                    out.write(new byte[]{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); // general failure
                    out.flush();
                    return;
                }

                Socket upstreamTarget = new Socket(host, port);
                out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); // succeeded
                out.flush();

                Thread pump = new Thread(() -> pump(socket, upstreamTarget), "FakeUpstreamSocks-Pump");
                pump.setDaemon(true);
                pump.start();
                pump(upstreamTarget, socket);
                upstreamTarget.close();
            } catch (IOException ignored) {
                // connection-level failure - normal for the failure-path test
            }
        }

        private static void pump(Socket from, Socket to) {
            try {
                InputStream in = from.getInputStream();
                OutputStream out = to.getOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                    out.flush();
                }
            } catch (IOException ignored) {
            } finally {
                try { to.shutdownOutput(); } catch (IOException ignored) { }
            }
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
}