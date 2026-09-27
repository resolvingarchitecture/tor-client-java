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
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Exercises {@link TorHttpClient} against a fake upstream SOCKS5 server (standing in for
 * {@link TorSocksRelay}/the real Tor daemon) and a fake plain-HTTP target - no live Tor daemon
 * or TLS needed. The point of every test here is the same one {@link TorSocksRelayTest}
 * makes for the relay itself: what actually goes out over the wire, not just "did the call
 * succeed."
 */
class TorHttpClientTest {

    private FakeUpstreamSocks upstream;
    private FakeHttpServer target;

    @AfterEach
    void tearDown() {
        if (upstream != null) upstream.shutdown();
        if (target != null) target.shutdown();
    }

    @Test
    void sendsTheHostnameUnresolvedNeverALocallyResolvedIp() throws Exception {
        target = new FakeHttpServer("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        target.start();
        upstream = new FakeUpstreamSocks("127.0.0.1", target.port());
        upstream.start();

        TorHttpClient client = new TorHttpClient();
        client.setProxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", upstream.port())));

        byte[] body = client.request("http://some.hostname.example.invalid/path");

        assertArrayEquals("ok".getBytes(StandardCharsets.US_ASCII), body);
        // The whole point: the upstream SOCKS server saw a domain-name CONNECT target, not an
        // IP - proving this device's own resolver never touched "some.hostname.example.invalid".
        assertEquals("some.hostname.example.invalid", upstream.lastRequestedHost());
    }

    @Test
    void parsesAFixedLengthResponseBody() throws Exception {
        target = new FakeHttpServer("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
        target.start();
        upstream = new FakeUpstreamSocks("127.0.0.1", target.port());
        upstream.start();

        TorHttpClient client = new TorHttpClient();
        client.setProxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", upstream.port())));

        assertArrayEquals("hello".getBytes(StandardCharsets.US_ASCII), client.request("http://target.example.invalid/"));
    }

    @Test
    void parsesAChunkedResponseBody() throws Exception {
        target = new FakeHttpServer("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n");
        target.start();
        upstream = new FakeUpstreamSocks("127.0.0.1", target.port());
        upstream.start();

        TorHttpClient client = new TorHttpClient();
        client.setProxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", upstream.port())));

        assertArrayEquals("hello!".getBytes(StandardCharsets.US_ASCII), client.request("http://target.example.invalid/"));
    }

    @Test
    void parsesAConnectionCloseDelimitedBody() throws Exception {
        target = new FakeHttpServer("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nno-length-header");
        target.start();
        upstream = new FakeUpstreamSocks("127.0.0.1", target.port());
        upstream.start();

        TorHttpClient client = new TorHttpClient();
        client.setProxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", upstream.port())));

        assertArrayEquals("no-length-header".getBytes(StandardCharsets.US_ASCII), client.request("http://target.example.invalid/"));
    }

    @Test
    void returnsNullWhenTheProxyPortIsNotOpen() {
        TorHttpClient client = new TorHttpClient();
        client.setProxy(new Proxy(Proxy.Type.SOCKS, new InetSocketAddress("127.0.0.1", freePort())));
        assertNull(client.request("http://target.example.invalid/"));
    }

    private static int freePort() {
        try (ServerSocket s = new ServerSocket(0)) {
            return s.getLocalPort();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /** Serves one fixed HTTP/1.1 response, verbatim, to every connection - just enough to drive {@link TorHttpClient}'s response parsing. */
    private static final class FakeHttpServer {
        private final String response;
        private ServerSocket server;
        private final Thread thread = new Thread(this::run, "FakeHttpServer");

        FakeHttpServer(String response) {
            this.response = response;
        }

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
                    // Never reads the request - this fixture only cares what it sends back.
                    OutputStream out = c.getOutputStream();
                    out.write(response.getBytes(StandardCharsets.US_ASCII));
                    out.flush();
                } catch (IOException ignored) {
                    // closed - stop accepting
                }
            }
        }
    }

    /**
     * A minimal SOCKS5 server that only handles CONNECT, always succeeds, and relays to a fixed
     * upstream {@code host:port} regardless of what the client actually asked to connect to -
     * {@link #lastRequestedHost()} records what the client sent so a test can assert on it.
     */
    private static final class FakeUpstreamSocks {
        private final String upstreamHost;
        private final int upstreamPort;
        private final AtomicReference<String> lastRequestedHost = new AtomicReference<>();
        private ServerSocket server;
        private final Thread thread = new Thread(this::run, "FakeUpstreamSocks");

        FakeUpstreamSocks(String upstreamHost, int upstreamPort) {
            this.upstreamHost = upstreamHost;
            this.upstreamPort = upstreamPort;
        }

        void start() throws IOException {
            server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
            thread.setDaemon(true);
            thread.start();
        }

        int port() { return server.getLocalPort(); }

        String lastRequestedHost() { return lastRequestedHost.get(); }

        void shutdown() {
            try { server.close(); } catch (IOException ignored) { }
        }

        private void run() {
            while (!server.isClosed()) {
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
                int cmd = in.read();
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
                in.read(); in.read(); // requested port - unused, always relays to the fixed upstream
                lastRequestedHost.set(host);
                if (cmd != 0x01) return; // CONNECT only

                Socket upstreamTarget = new Socket(upstreamHost, upstreamPort);
                out.write(new byte[]{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); // succeeded
                out.flush();

                Thread pump = new Thread(() -> pump(socket, upstreamTarget), "FakeUpstreamSocks-Pump");
                pump.setDaemon(true);
                pump.start();
                pump(upstreamTarget, socket);
                upstreamTarget.close();
            } catch (IOException ignored) {
                // connection-level failure - not what these tests exercise
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