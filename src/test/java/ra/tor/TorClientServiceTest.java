package ra.tor;

import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import ra.common.DLC;
import ra.common.Envelope;
import ra.common.network.NetworkBuilderStrategy;
import ra.http.client.HTTPClientService;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Properties;
import java.util.logging.Logger;

import static ra.http.client.HTTPClientService.RA_HTTP_CLIENT_TRUST_ALL;

public class TorClientServiceTest {

    private static final Logger LOG = Logger.getLogger(TorClientServiceTest.class.getName());

    private static HTTPClientService service;
    private static MockProducer producer;
    private static Properties props;
    private static boolean ready = false;

    @BeforeClass
    public static void init() {
        LOG.info("Init...");
        props = new Properties();

        producer = new MockProducer();
        NetworkBuilderStrategy strategy = new NetworkBuilderStrategy();
        strategy.maxKnownPeers = 5;
        strategy.minKnownPeers = 1;
        service = new TORClientService(producer, null, strategy);
        ready = service.start(props);
    }

    @AfterClass
    public static void tearDown() {
        LOG.info("Teardown...");
        service.gracefulShutdown();
    }

    @Test
    public void verifyInitializedTest() {
        Assert.assertTrue(ready);
    }

    @Test
    public void verifyConnected() {
        Envelope envelope = Envelope.documentFactory();
        try {
            // Secure Drop Onion Site
            envelope.setURL(new URL("http://sdolvtfhatvsysc6l34d65ymdwxcujausv7k5jk4cy5ttzhjoi6fzvyd.onion"));
        } catch (MalformedURLException e) {
            LOG.severe(e.getLocalizedMessage());
            Assert.fail();
            return;
        }
        envelope.setHeader(Envelope.HEADER_CONTENT_TYPE, "text/html");
        envelope.setAction(Envelope.Action.GET);
        service.sendOut(envelope);
        String html = new String((byte[]) DLC.getContent(envelope));
        LOG.info(html);
        Assert.assertTrue(html.contains("<title>\n" +
                "\t\t\t\t\n" +
                "\t\t\t\t\tShare and accept documents securely\n" +
                "\t\t\t\t\n" +
                "\t\t\t\t\n" +
                "\t\t\t\t\t- SecureDrop\n" +
                "\t\t\t\t\n" +
                "\t\t\t</title>"));
    }

}
