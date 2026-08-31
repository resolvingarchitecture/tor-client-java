package ra.tor;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.ServerSocket;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class LocalTorDetectorTest {

    @Test
    public void nothingListening() {
        LocalTorDetector d = new LocalTorDetector("127.0.0.1", 9098, 9099, 300);
        assertFalse(d.isSocksReachable());
        assertFalse(d.isControlReachable());
        assertFalse(d.isLocalTorRunning());
    }

    @Test
    public void detectsOpenSockets() throws IOException {
        try (ServerSocket socks = new ServerSocket(0);
             ServerSocket control = new ServerSocket(0)) {
            LocalTorDetector d = new LocalTorDetector(
                    "127.0.0.1", socks.getLocalPort(), control.getLocalPort(), 500);
            assertTrue(d.isSocksReachable());
            assertTrue(d.isControlReachable());
            assertTrue(d.isLocalTorRunning());
        }
    }
}
