package ra.tor;

import ra.common.messaging.MessageProducer;
import ra.common.network.*;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusListener;

import ra.common.Envelope;
import ra.http.client.HTTPClientService;
import ra.util.Config;
import ra.util.Wait;

import java.io.File;
import java.io.IOException;
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

    public TORClientService(MessageProducer producer, ServiceStatusListener listener, NetworkBuilderStrategy strategy) {
        super(producer, listener, strategy);
    }

//    public Boolean sendOut(Envelope e) {
//        LOG.info("Tor Sensor sending request...");
//        NetworkClientSession sensorSession = establishSession(null, true);
//        if(sensorSession==null) {
//            return false;
//        }
//        boolean successful = sensorSession.send(e);
//        if (successful) {
//            LOG.info("Tor Sensor successful response received.");
//            if (!getServiceStatus().equals(ServiceStatus.RUNNING)) {
//                LOG.info("Tor Network status changed back to CONNECTED.");
//                updateStatus(ServiceStatus.RUNNING);
//            }
//        }
//        return successful;
//    }

//    public NetworkClientSession establishSession(String address, Boolean autoConnect) {
//        if(address==null) {
//            address = "127.0.0.1";
//        }
//        if(sessions.get(address)==null) {
//            NetworkClientSession networkSession = new TORSensorSessionLocal(this);
//
//            if(networkSession.init(config) && networkSession.open(address)) {
//                if (autoConnect) {
//                    networkSession.connect();
//                }
//                sessions.put(address, networkSession);
//                return sessions.get(address);
//            }
//        }
//        return null;
//    }

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

//        NetworkClientSession torSession = null;
//        do {
//            torSession = establishSession("127.0.0.1", true);
//            LOG.info(getStatus().name());
//            if(getStatus()==SensorStatus.NETWORK_UNAVAILABLE) {
//                if(!embedded) {
//                    LOG.info("TOR Unavailable and not embedded; attempting to start TOR externally...");
//                    try {
//                        tor = Runtime.getRuntime().exec("tor");
//                        LOG.info("TOR (pid="+tor.pid()+") started. Waiting a few seconds to warm up...");
//                        // Give some room for TOR to start up
//                        updateStatus(SensorStatus.NETWORK_WARMUP);
//                        Wait.aSec(3);
//                    } catch (IOException e) {
//                        LOG.warning(e.getLocalizedMessage());
//                    }
//                }
//            } else if(getServiceStatus()!=ServiceStatus.NETWORK_CONNECTING) {
//                updateStatus(SensorStatus.NETWORK_CONNECTING);
//            }
//        } while(torSession == null || !torSession.isConnected());
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
