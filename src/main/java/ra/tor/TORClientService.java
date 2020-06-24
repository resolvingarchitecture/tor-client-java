package ra.tor;

import ra.common.messaging.MessageProducer;
import ra.common.network.NetworkPacket;
import ra.common.network.NetworkPeer;
import ra.common.network.NetworkSession;
import ra.common.network.NetworkStatus;
import ra.common.service.BaseService;
import ra.common.service.ServiceStatusListener;
import ra.tor.embedded.TORSessionEmbedded;
import ra.tor.local.TORSensorSessionLocal;

import ra.common.Envelope;
import ra.util.Wait;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Sets up an HttpClientSensor with the local Tor instance as a proxy (127.0.0.1:9150).
 *
 * TODO: Add local node as Tor Hidden Service accepting local Tor calls
 *
 */
public final class TORClientService extends BaseService {

    private static final Logger LOG = Logger.getLogger(TORClientService.class.getName());

    public static final String TOR_ROUTER_EMBEDDED = "settings.network.tor.routerEmbedded";
    public static final String TOR_HIDDENSERVICES_CONFIG = "settings.network.tor.hiddenServicesConfig";
    public static final String TOR_HIDDENSERVICE_CONFIG = "settings.network.tor.hiddenServiceConfig";

    public static final NetworkPeer seedATOR;
    private Process tor;

    static {
        seedATOR = new NetworkPeer(TORClientService.class.getName());
        seedATOR.setId("+sKVViuz2FPsl/XQ+Da/ivbNfOI=");
        seedATOR.setPort(35910); // virtual port
        seedATOR.getDid().getPublicKey().setAddress("5pdavjxcwrfx2meu");
        seedATOR.getDid().getPublicKey().setFingerprint("5pdavjxcwrfx2meu");
        seedATOR.getDid().getPublicKey().setType("RSA2048");
        seedATOR.getDid().getPublicKey().isIdentityKey(true);
        seedATOR.getDid().getPublicKey().setBase64Encoded(true);
    }

    private File sensorDir;
    private boolean embedded = false;
    private final Map<String, NetworkSession> sessions = new HashMap<>();
    private Thread taskRunnerThread;

    public TORClientService() {
    }

    public TORClientService(MessageProducer producer, ServiceStatusListener listener) {
        super(producer, listener);
    }

    public boolean sendOut(NetworkPacket packet) {
        LOG.info("Tor Sensor sending request...");
        NetworkSession sensorSession = establishSession(null, true);
        if(sensorSession==null) {
            return false;
        }
        boolean successful = sensorSession.send(packet);
        if (successful) {
            LOG.info("Tor Sensor successful response received.");
            if (!getStatus().equals(NetworkStatus.NETWORK_CONNECTED)) {
                LOG.info("Tor Network status changed back to CONNECTED.");
                updateStatus(NetworkStatus.NETWORK_CONNECTED);
            }
        }
        return successful;
    }

    public NetworkSession establishSession(String address, Boolean autoConnect) {
        if(address==null) {
            address = "127.0.0.1";
        }
        if(sessions.get(address)==null) {
            NetworkSession networkSession = embedded ? new TORSessionEmbedded(this) : new TORSensorSessionLocal(this);

            if(networkSession.init(config) && networkSession.open(address)) {
                if (autoConnect) {
                    networkSession.connect();
                }
                sessions.put(address, networkSession);
                return sessions.get(address);
            }
        }
        return null;
    }

    @Override
    public void updateState(NetworkState networkState) {
        LOG.warning("Not implemented.");
    }

    @Override
    public boolean sendIn(Envelope envelope) {
        return super.sendIn(envelope);
    }

    @Override
    public boolean start(Properties properties) {
        LOG.info("Starting TOR Sensor...");
        updateStatus(SensorStatus.INITIALIZING);
        this.properties = properties;
        String sensorsDirStr = properties.getProperty("1m5.dir.sensors");
        if (sensorsDirStr == null) {
            LOG.warning("1m5.dir.sensors property is null. Please set prior to instantiating Tor Sensor.");
            return false;
        }
        try {
            sensorDir = new File(new File(sensorsDirStr), "tor");
            if (!sensorDir.exists() && !sensorDir.mkdir()) {
                LOG.warning("Unable to create Tor sensor directory.");
                return false;
            } else {
                properties.put("1m5.dir.sensors.tor", sensorDir.getCanonicalPath());
            }
        } catch (IOException e) {
            LOG.warning("IOException caught while building Tor sensor directory: \n" + e.getLocalizedMessage());
            return false;
        }

        Wait.aMs(500); // Give the infrastructure a bit of breathing room before saving seeds
        if(sensorManager.getPeerManager().savePeer(seedATOR, true)) {
            networkState.seeds.add(seedATOR);
        }

        updateStatus(SensorStatus.STARTING);

        embedded = "true".equals(properties.getProperty(TOR_ROUTER_EMBEDDED));
        networkState.params.put(TOR_ROUTER_EMBEDDED, String.valueOf(embedded));

        SensorSession torSession = null;
        do {
            torSession = establishSession("127.0.0.1", true);
            LOG.info(getStatus().name());
            if(getStatus()==SensorStatus.NETWORK_UNAVAILABLE) {
                if(!embedded) {
                    LOG.info("TOR Unavailable and not embedded; attempting to start TOR externally...");
                    try {
                        tor = Runtime.getRuntime().exec("tor");
                        LOG.info("TOR (pid="+tor.pid()+") started. Waiting a few seconds to warm up...");
                        // Give some room for TOR to start up
                        updateStatus(SensorStatus.NETWORK_WARMUP);
                        Wait.aSec(3);
                    } catch (IOException e) {
                        LOG.warning(e.getLocalizedMessage());
                    }
                }
            } else if(getStatus()!=SensorStatus.NETWORK_CONNECTING) {
                updateStatus(SensorStatus.NETWORK_CONNECTING);
            }
        } while(torSession == null || !torSession.isConnected());
        updateStatus(SensorStatus.NETWORK_CONNECTED);
//        kickOffDiscovery();
        return true;
    }

    private void kickOffDiscovery() {
        // Setup Discovery
        discovery = new NetworkPeerDiscovery(taskRunner, this);
        taskRunner.addTask(discovery);
        taskRunnerThread = new Thread(taskRunner);
        taskRunnerThread.setDaemon(true);
        taskRunnerThread.setName("TORSensor-TaskRunnerThread");
        taskRunnerThread.start();
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
        updateStatus(SensorStatus.SHUTTING_DOWN);
        if(taskRunnerThread!=null)
            taskRunnerThread.interrupt();
        for(SensorSession session : sessions.values()) {
            session.disconnect();
            session.close();
        }
        sessions.clear();
        if(tor!=null) {
            tor.destroyForcibly();
            tor=null;
        }
        updateStatus(SensorStatus.SHUTDOWN);
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        updateStatus(SensorStatus.GRACEFULLY_SHUTTING_DOWN);
        if(taskRunnerThread!=null)
            taskRunnerThread.interrupt();
        for(SensorSession session : sessions.values()) {
            session.disconnect();
            session.close();
        }
        sessions.clear();
        if(tor!=null) {
            tor.destroy();
            tor=null;
        }
        updateStatus(SensorStatus.GRACEFULLY_SHUTDOWN);
        return true;
    }
}
