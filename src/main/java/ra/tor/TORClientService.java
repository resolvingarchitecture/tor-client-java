package ra.tor;

import ra.common.DLC;
import ra.common.Envelope;
import ra.common.messaging.MessageProducer;
import ra.common.network.*;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;

import ra.http.client.HTTPClientService;
import ra.util.Config;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.*;
import java.util.logging.Logger;

/**
 * Sets up an HttpClientSensor with the local Tor instance as a proxy (127.0.0.1:9150).
 */
public final class TORClientService extends HTTPClientService {

    private static final Logger LOG = Logger.getLogger(TORClientService.class.getName());

    public static final String HOST = "127.0.0.1";
    public static final Integer PORT_SOCKS = 9050;
    public static final Integer PORT_CONTROL = 9051;
    //    public static final Integer PORT_CONTROL = 9100;
    public static final Integer PORT_SOCKS_BROWSER = 9150;
    public static final Integer PORT_HIDDEN_SERVICE = 9151;

    private Process tor;
    private final Map<String, NetworkClientSession> sessions = new HashMap<>();
    private Thread taskRunnerThread;
    private Properties config;

    public TORClientService(MessageProducer producer, ServiceStatusObserver observer) {
        super("Tor", producer, observer);
    }

    @Override
    public boolean start(Properties properties) {
        LOG.info("Starting TOR Sensor...");
        updateStatus(ServiceStatus.INITIALIZING);
        try {
            this.config = Config.loadFromClasspath("ra-tor-client.config", properties, false);
        } catch (Exception e) {
            LOG.warning(e.getLocalizedMessage());
            config = properties;
        }

        proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(HOST, PORT_SOCKS));

        super.start(properties);
        updateStatus(ServiceStatus.RUNNING);
//        kickOffDiscovery();
        return true;
    }

    private void kickOffDiscovery() {
        // Setup Discovery
//        discovery = new NetworkPeerDiscovery(taskRunner, this);
//        taskRunner.addTask(discovery);
//        taskRunnerThread = new Thread(taskRunner);
//        taskRunnerThread.setDaemon(true);
//        taskRunnerThread.setName("TORSensor-TaskRunnerThread");
//        taskRunnerThread.start();
    }

    @Override
    public boolean pause() {
        return false;
    }

    @Override
    public boolean unpause() {
        return false;
    }

    @Override
    public boolean restart() {
        return false;
    }

    @Override
    public boolean shutdown() {
        updateStatus(ServiceStatus.SHUTTING_DOWN);
        super.shutdown();
//        if(taskRunnerThread!=null)
//            taskRunnerThread.interrupt();
//        for(NetworkClientSession session : sessions.values()) {
//            session.disconnect();
//            session.close();
//        }
//        sessions.clear();
//        if(tor!=null) {
//            tor.destroyForcibly();
//            tor=null;
//        }
        updateStatus(ServiceStatus.SHUTDOWN);
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        updateStatus(ServiceStatus.GRACEFULLY_SHUTTING_DOWN);
        super.gracefulShutdown();
//        if(taskRunnerThread!=null)
//            taskRunnerThread.interrupt();
//        for(NetworkClientSession session : sessions.values()) {
//            session.disconnect();
//            session.close();
//        }
//        sessions.clear();
//        if(tor!=null) {
//            tor.destroy();
//            tor=null;
//        }
        updateStatus(ServiceStatus.GRACEFULLY_SHUTDOWN);
        return true;
    }
}
