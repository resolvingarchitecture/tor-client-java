package ra.tor;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.logging.Logger;

import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * A plain HTTP(S) GET/POST client for callers that already have a Tor SOCKS proxy (this
 * process's own {@link TORClientService}, a {@link TorSocksRelay} layered in front of it, or any
 * other SOCKS proxy a caller hands in) and want to fetch an ordinary web URL through it - not a
 * Tor peer connection or hidden-service traffic, which stay each consumer's own concern.
 *
 * <p><b>Why this exists instead of {@code HttpURLConnection.openConnection(proxy)}:</b> the JDK's
 * {@code sun.net.NetworkClient} connect path builds a <em>resolved</em> {@link InetSocketAddress}
 * for the target host before the SOCKS layer ever sees it, so only the already-resolved IP
 * address travels over Tor - the hostname itself never does. That leaks the DNS lookup outside
 * Tor entirely, and it also produces real connectivity failures a generic "the network is flaky"
 * wouldn't: an IP resolved for the caller's own network vantage point (local/carrier DNS, often
 * anycast/CDN-steered) is frequently unreachable or slow from a Tor exit relay's very different
 * one - observed in a live two-device debug session of an app consuming this library as a SOCKS
 * "Host unreachable" and connect timeouts against ordinary HTTPS APIs. {@link TorSocksRelay
 * #handle} already gets this right one hop downstream, forwarding a CONNECT with a domain-name
 * target on to the real Tor daemon still unresolved via its own {@code InetSocketAddress
 * .createUnresolved} call - but only once a request reaches it as a domain name in the first
 * place, which {@code HttpURLConnection} never sends. This class connects with {@code
 * InetSocketAddress.createUnresolved(host, port)} directly - the JDK's SOCKS {@link Proxy} client
 * recognizes an unresolved address and sends it to the proxy as a hostname, letting Tor's exit
 * relay resolve it instead - and speaks HTTP/1.1 by hand over the result, since {@code
 * HttpURLConnection} gives no way to hand it an already-connected, already-unresolved socket.
 */
public final class TorHttpClient {

    private static final Logger LOG = Logger.getLogger(TorHttpClient.class.getName());
    private static final int PROXY_OPEN_CHECK_TIMEOUT_MS = 1000;
    private static final int CONNECT_TIMEOUT_MS = 30_000;
    private static final int READ_TIMEOUT_MS = 60_000;

    /**
     * A generic, widely-shared value - deliberately not reflecting the calling device/app -
     * matches Tor Browser's own practice of giving every user an identical, unremarkable
     * fingerprint; same value {@code ra.http.HTTPService} defaults to for consistency.
     */
    private static final String DEFAULT_USER_AGENT =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0";

    private volatile Proxy proxy;

    public void setProxy(Proxy proxy) {
        this.proxy = proxy;
    }

    /** POST (or other) {@code body} to {@code url} through the SOCKS proxy. Returns the HTTP status code, or -1 on failure. */
    public int send(String url, String httpMethod, byte[] body) {
        if (!isProxyOpen()) {
            LOG.warning("SOCKS proxy not open.");
            return -1;
        }
        try {
            return execute(url, httpMethod, body).statusCode;
        } catch (IOException e) {
            LOG.warning("send to " + url + ": " + e.getMessage());
            return -1;
        }
    }

    /** GET {@code url} through the SOCKS proxy. Returns the response body, or null on failure. */
    public byte[] request(String url) {
        if (!isProxyOpen()) {
            LOG.warning("SOCKS proxy not open.");
            return null;
        }
        try {
            return execute(url, "GET", null).body;
        } catch (IOException e) {
            LOG.warning("request to " + url + ": " + e.getMessage());
            return null;
        }
    }

    private static final class HttpResponse {
        final int statusCode;
        final byte[] body;
        HttpResponse(int statusCode, byte[] body) {
            this.statusCode = statusCode;
            this.body = body;
        }
    }

    /**
     * Speaks HTTP/1.1 by hand over a socket connected through {@link #proxy} with the target host
     * left {@link InetSocketAddress#isUnresolved() unresolved} - see this class's javadoc for why.
     * No redirect following, no persistent connections (every call gets its own socket, {@code
     * Connection: close}) - a fetch-once, one-shot shape, which is all every known caller needs.
     */
    HttpResponse execute(String url, String httpMethod, byte[] body) throws IOException {
        URL parsed = new URL(url);
        boolean tls = "https".equalsIgnoreCase(parsed.getProtocol());
        String host = parsed.getHost();
        int port = parsed.getPort() != -1 ? parsed.getPort() : (tls ? 443 : 80);
        String path = parsed.getFile();
        if (path == null || path.isEmpty()) path = "/";

        Socket socket = new Socket(proxy);
        Socket active = socket; // reassigned to the TLS layer below when `tls` - always the one actually closed
        try {
            socket.connect(InetSocketAddress.createUnresolved(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(READ_TIMEOUT_MS);
            if (tls) {
                SSLSocketFactory sslFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket sslSocket = (SSLSocket) sslFactory.createSocket(socket, host, port, true);
                SSLParameters params = sslSocket.getSSLParameters();
                params.setEndpointIdentificationAlgorithm("HTTPS"); // real hostname verification against the cert
                sslSocket.setSSLParameters(params);
                sslSocket.startHandshake();
                active = sslSocket; // autoClose=true above means closing this also closes `socket`
            }
            writeRequest(active.getOutputStream(), httpMethod, host, path, body);
            return readResponse(active.getInputStream());
        } finally {
            try { active.close(); } catch (IOException ignored) { }
        }
    }

    private void writeRequest(OutputStream out, String method, String host, String path, byte[] body) throws IOException {
        StringBuilder head = new StringBuilder();
        head.append(method).append(' ').append(path).append(" HTTP/1.1\r\n");
        head.append("Host: ").append(host).append("\r\n");
        head.append("User-Agent: ").append(DEFAULT_USER_AGENT).append("\r\n");
        head.append("Accept: */*\r\n");
        head.append("Connection: close\r\n");
        if (body != null) head.append("Content-Length: ").append(body.length).append("\r\n");
        head.append("\r\n");
        out.write(head.toString().getBytes(StandardCharsets.US_ASCII));
        if (body != null) out.write(body);
        out.flush();
    }

    private HttpResponse readResponse(InputStream rawIn) throws IOException {
        InputStream in = new BufferedInputStream(rawIn);
        String statusLine = readLine(in);
        if (statusLine == null) throw new IOException("empty response");
        int statusCode = parseStatusCode(statusLine);

        Map<String, String> headers = new HashMap<>();
        String line;
        while ((line = readLine(in)) != null && !line.isEmpty()) {
            int colon = line.indexOf(':');
            if (colon > 0) {
                headers.put(line.substring(0, colon).trim().toLowerCase(Locale.ROOT), line.substring(colon + 1).trim());
            }
        }

        byte[] body;
        String transferEncoding = headers.get("transfer-encoding");
        if (transferEncoding != null && transferEncoding.toLowerCase(Locale.ROOT).contains("chunked")) {
            body = readChunkedBody(in);
        } else {
            String contentLength = headers.get("content-length");
            body = contentLength != null ? readFixedBody(in, Integer.parseInt(contentLength.trim())) : readUntilClose(in);
        }
        return new HttpResponse(statusCode, body);
    }

    private static int parseStatusCode(String statusLine) throws IOException {
        String[] parts = statusLine.split(" ", 3);
        if (parts.length < 2) throw new IOException("malformed status line: " + statusLine);
        try {
            return Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            throw new IOException("malformed status line: " + statusLine);
        }
    }

    private static byte[] readFixedBody(InputStream in, int length) throws IOException {
        byte[] buf = new byte[length];
        int off = 0;
        while (off < length) {
            int n = in.read(buf, off, length - off);
            if (n < 0) break;
            off += n;
        }
        return off == length ? buf : Arrays.copyOf(buf, off);
    }

    private static byte[] readUntilClose(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static byte[] readChunkedBody(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while (true) {
            String sizeLine = readLine(in);
            if (sizeLine == null) break;
            int semicolon = sizeLine.indexOf(';');
            String sizeToken = semicolon >= 0 ? sizeLine.substring(0, semicolon) : sizeLine;
            int size;
            try {
                size = Integer.parseInt(sizeToken.trim(), 16);
            } catch (NumberFormatException e) {
                throw new IOException("malformed chunk size: " + sizeLine);
            }
            if (size == 0) {
                while ((sizeLine = readLine(in)) != null && !sizeLine.isEmpty()) { /* discard trailing headers */ }
                break;
            }
            out.write(readFixedBody(in, size));
            readLine(in); // trailing CRLF after each chunk's data
        }
        return out.toByteArray();
    }

    /** Reads a single CRLF- (or bare LF-) terminated line as US-ASCII text; null at end of stream with nothing read. */
    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int b;
        boolean any = false;
        while ((b = in.read()) != -1) {
            any = true;
            if (b == '\n') break;
            if (b != '\r') line.write(b);
        }
        if (!any && line.size() == 0) return null;
        return line.toString(StandardCharsets.US_ASCII.name());
    }

    private boolean isProxyOpen() {
        Proxy current = proxy;
        if (current == null || !(current.address() instanceof InetSocketAddress)) return false;
        InetSocketAddress address = (InetSocketAddress) current.address();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(address.getHostString(), address.getPort()), PROXY_OPEN_CHECK_TIMEOUT_MS);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}