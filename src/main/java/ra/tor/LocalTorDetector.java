package ra.tor;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Logger;

/**
 * Detects a local Tor daemon so {@link TORClientService} can fail fast with a
 * clear message instead of a confusing control-connection error.
 *
 * <p>Tor is a C daemon (unlike I2P's pure-Java router), so this client only ever
 * uses a <b>local</b> instance - installed and running on this host - via its
 * SOCKS proxy (9050) and control port (9051). See README.md for the daemon setup.
 * This is the JVM analogue of {@code 1m5-android}'s {@code TorLocal} (which binds
 * to Orbot).
 */
public final class LocalTorDetector {

    private static final Logger LOG = Logger.getLogger(LocalTorDetector.class.getName());

    private final String host;
    private final int socksPort;
    private final int controlPort;
    private final int timeoutMs;

    public LocalTorDetector() {
        this(TORClientService.HOST, TORClientService.PORT_SOCKS, TORClientService.PORT_CONTROL, 750);
    }

    public LocalTorDetector(String host, int socksPort, int controlPort, int timeoutMs) {
        this.host = host;
        this.socksPort = socksPort;
        this.controlPort = controlPort;
        this.timeoutMs = timeoutMs;
    }

    public boolean isSocksReachable() {
        return reachable(socksPort);
    }

    public boolean isControlReachable() {
        return reachable(controlPort);
    }

    /** True only if both the SOCKS proxy and the control port answer. */
    public boolean isLocalTorRunning() {
        return isSocksReachable() && isControlReachable();
    }

    private boolean reachable(int port) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException e) {
            LOG.fine("Nothing on " + host + ":" + port + " (" + e.getMessage() + ")");
            return false;
        }
    }
}
