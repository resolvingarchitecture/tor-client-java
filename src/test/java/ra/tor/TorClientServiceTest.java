package ra.tor;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import ra.common.DLC;
import ra.common.Envelope;
import ra.util.Wait;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

public class TorClientServiceTest {

    private static final Logger LOG = Logger.getLogger(TorClientServiceTest.class.getName());

    private static TORClientService service;
    private static MockProducer producer;
    private static Properties props;
    private static boolean ready = false;

    @BeforeAll
    public static void init() {
        LOG.info("Init...");
        props = new Properties();

        producer = new MockProducer();
        service = new TORClientService(producer, null);
        ready = service.start(props);
    }

    @AfterAll
    public static void tearDown() {
        LOG.info("Teardown...");
        service.gracefulShutdown();
    }

//    @Test
//    @Order(1)
//    public void verifyInitializedTest() {
//        if(!ready) {
//            LOG.warning("Service not ready - ensure Tor is running.");
//        }
//        assertTrue(ready);
//    }

    @Test
    @Order(2)
    public void verifyClient() {
        Envelope envelope = Envelope.documentFactory();
        try {
            // Secure Drop Onion Site
            envelope.setURL(new URL("http://sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion"));
        } catch (MalformedURLException e) {
            LOG.severe(e.getLocalizedMessage());
            fail();
            return;
        }
        envelope.setHeader(Envelope.HEADER_CONTENT_TYPE, "text/html");
        envelope.setAction(Envelope.Action.GET);
        service.sendOut(envelope);
        String html = new String((byte[]) DLC.getContent(envelope));
        LOG.info(html);
        String secureDropMessage = "Share and accept documents securely";
        if(!html.contains(secureDropMessage)) {
            LOG.warning("Verify Secure Drop onion site is accessible at: http://sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion and contains the following message: Share and accept documents securely");
        }
        assertTrue(html.contains(secureDropMessage));
    }

//    @Test
//    @Order(3)
//    public void verifyHiddenService() {
//        Envelope envelope = Envelope.documentFactory();
//        try {
//            // Local Hidden Service URL
//            envelope.setURL(new URL(service.getHiddenServiceURL()+"/test"));
//        } catch (MalformedURLException e) {
//            LOG.severe(e.getLocalizedMessage());
//            fail();
//            return;
//        }
//        envelope.setHeader(Envelope.HEADER_CONTENT_TYPE, "text/html");
//        envelope.setAction(Envelope.Action.GET);
//        Wait.aSec(30); // Wait 30 seconds to give time for TOR to publish address
//        service.sendOut(envelope);
//        String html = new String((byte[]) DLC.getContent(envelope));
//        LOG.info(html);
//        assertEquals("<html><body>TORHS Available</body></html>", html);
//    }

}
