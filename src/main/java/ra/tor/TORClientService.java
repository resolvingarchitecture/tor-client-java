package ra.tor;

import ra.common.messaging.MessageProducer;
import ra.common.network.*;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;

import ra.http.EnvelopeJSONDataHandler;
import ra.http.HTTPService;
import ra.common.Config;
import ra.common.FileUtil;
import ra.common.RandomUtil;
import ra.common.SystemSettings;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Sets up an HttpClientSensor with the local Tor instance as a proxy (127.0.0.1:9150).
 */
public final class TORClientService extends HTTPService {

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

    private TORControlConnection controlConnection;
    private TORHiddenService torHiddenService = null;

    private File torUserHome;
    private File torConfigHome;
    private File torrcFile;
    private File privKeyFile;
    private File hiddenServiceDir;
    private File hiddenServiceFile;

    public TORClientService() {
        super();
        getNetworkState().network = Network.Tor;
        getNetworkState().localPeer = new NetworkPeer(Network.Tor);
    }

    public TORClientService(MessageProducer producer, ServiceStatusObserver observer) {
        super(Network.Tor, producer, observer);
    }

    TORHiddenService getTorHiddenService() {
        return torHiddenService;
    }

    public int randomTORPort() {
        return RandomUtil.nextRandomInteger(10000, 65535);
    }

    private TORControlConnection getControlConnection() throws IOException {
        Socket s = new Socket("127.0.0.1", PORT_CONTROL);
        TORControlConnection conn = new TORControlConnection(s);
        conn.authenticate(new byte[0]);
        return conn;
    }

    public String getHiddenServiceId() {
        return torHiddenService.serviceId;
    }

    public String getHiddenServiceURL() {
        return "http://"+torHiddenService.serviceId+".onion";
    }

    @Override
    public boolean start(Properties properties) {
        LOG.info("Initializing TOR Client Service...");
        updateStatus(ServiceStatus.STARTING);
        try {
            config = Config.loadAll(properties,"ra-tor-client.config");
        } catch (Exception e) {
            LOG.severe(e.getLocalizedMessage());
            return false;
        }

        proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(HOST, PORT_SOCKS));

        LOG.info("Starting underlying HTTP Service...");
        super.start(config);

        LOG.info("Initializing TOR Hidden Service...");
        torUserHome = new File(SystemSettings.getUserHomeDir(), ".tor");
        if(!torUserHome.exists()) {
            LOG.severe("TOR User Home does not exist => TOR not installed.");
            return false;
        }

        torConfigHome = new File(config.getProperty("ra.tor.config.home"));
        if(!torConfigHome.exists()) {
            LOG.severe("TOR Config Home /etc/tor does not exist => TOR not installed.");
            return false;
        }

        torrcFile = new File(torConfigHome, "torrc");
        if(!torrcFile.exists()) {
            LOG.severe("TOR Config File /etc/tor/torrc does not exist => TOR not installed.");
            return false;
        }

        if(config.getProperty("ra.tor.hs.name")==null) {
            LOG.severe("ra.tor.hs.name (hidden service directory name) is a required property.");
            return false;
        }
        hiddenServiceDir = new File(getServiceDirectory(), config.getProperty("ra.tor.hs.name") );
        if(!hiddenServiceDir.exists() && !hiddenServiceDir.mkdir()) {
            LOG.severe("TOR hidden service directory does not exist and unable to create.");
            return false;
        }

        privKeyFile = new File(hiddenServiceDir, "private_key");

        torHiddenService = new TORHiddenService();

        hiddenServiceFile = new File(getServiceDirectory(), "torhs");
        if(hiddenServiceFile.exists()) {
            try {
                String json = new String(FileUtil.readFile(hiddenServiceFile.getAbsolutePath()));
                torHiddenService.fromJSON(json);
            } catch (IOException e) {
                LOG.severe(e.getLocalizedMessage());
                return false;
            }
        }

        boolean destroyHiddenService = "true".equals(config.getProperty("ra.tor.hs.privkey.destroy"));
        if(destroyHiddenService && privKeyFile.exists()) {
            LOG.info("Destroying Hidden Service....");
            if(!privKeyFile.delete()) {
                LOG.severe("Requested to destroy hidden service private key and unable to. Delete manually and restart. Stopping startup.");
                return false;
            }
        } else if(privKeyFile.exists()) {
            LOG.info("Tor Hidden Service private key found, loading...");
            byte[] bytes = null;
            try {
                bytes = FileUtil.readFile(privKeyFile.getAbsolutePath());
            } catch (IOException e) {
                LOG.warning(e.getLocalizedMessage());
                // Ensure private key is removed
                privKeyFile.delete();
            }
            if(bytes!=null) {
                torHiddenService.privateKey = new String(bytes);
            }
            if(torHiddenService.virtualPort==null
                    || torHiddenService.targetPort==null
                    || torHiddenService.serviceId==null
                    || torHiddenService.privateKey==null) {
                // Probably corrupted file
                LOG.info("Tor key found but likely corrupted, deleting....");
                if(!privKeyFile.delete()) {
                    LOG.severe("Unable to delete likely corrupted hidden service private key. Delete manually and restart. Stopping service start.");
                    return false;
                }
            }
        }
        LOG.info("Starting TOR Hidden Service...");
        try {
            updateNetworkStatus(NetworkStatus.CONNECTING);
            controlConnection = getControlConnection();
            Map<String, String> m = controlConnection.getInfo(Arrays.asList("stream-status", "orconn-status", "circuit-status", "version"));
//            Map<String, String> m = controlConnection.getInfo(Arrays.asList("version"));
            StringBuilder sb = new StringBuilder();
            sb.append("TOR config:");
            for (Iterator<Map.Entry<String, String>> i = m.entrySet().iterator(); i.hasNext(); ) {
                Map.Entry<String, String> e = i.next();
                sb.append("\n\t"+e.getKey()+"="+e.getValue());
            }
            LOG.info(sb.toString());
            controlConnection.setEventHandler(new TOREventHandler(torHiddenService, LOG));
            controlConnection.setEvents(Arrays.asList("CIRC", "ORCONN", "INFO", "NOTICE", "WARN", "ERR", "HS_DESC", "HS_DESC_CONTENT"));

            String handlerClass = config.getProperty("ra.tor.hs.handler");
            if(handlerClass==null) {
                handlerClass = EnvelopeJSONDataHandler.class.getName();
            }
            updateNetworkStatus(NetworkStatus.CONNECTED);
            if(torHiddenService.serviceId==null) {
                LOG.info("TOR Hidden Service private key does not exist, was unreadable, or requested to be destroyed, so creating new hidden service...");
                privKeyFile = new File(hiddenServiceDir, "private_key");
                int virtPort;
                if(config.getProperty("ra.tor.virtualPort")==null) {
                    virtPort = randomTORPort();
                } else {
                    virtPort = Integer.parseInt(config.getProperty("ra.tor.hs.virtualPort"));
                }
                int targetPort;
                if(config.getProperty("ra.tor.targetPort")==null) {
                    targetPort = randomTORPort();
                } else {
                    targetPort = Integer.parseInt(config.getProperty("ra.tor.hs.targetPort"));
                }
                if(launch("TORHS, API, localhost, " + targetPort + ", " + handlerClass)) {
                    torHiddenService = controlConnection.createHiddenService(virtPort, targetPort);
                    LOG.info("TOR Hidden Service Created: " + torHiddenService.serviceId
                            + " on virtualPort: " + torHiddenService.virtualPort
                            + " to targetPort: " + torHiddenService.targetPort);
                    getNetworkState().localPeer.getDid().getPublicKey().setAddress(torHiddenService.serviceId);
                    getNetworkState().targetPort = torHiddenService.targetPort;
                    getNetworkState().virtualPort = torHiddenService.virtualPort;
//                controlConnection.destroyHiddenService(hiddenService.serviceID);
//                hiddenService = controlConnection.createHiddenService(hiddenService.port, hiddenService.privateKey);
//                LOG.info("TOR Hidden Service Created: " + hiddenService.serviceID + " on port: "+hiddenService.port);
                    // Now save the private key
                    if (!privKeyFile.exists() && !privKeyFile.createNewFile()) {
                        LOG.warning("Unable to create file: " + privKeyFile.getAbsolutePath());
                        return false;
                    }
                    torHiddenService.readable(true);
                    torHiddenService.setCreatedAt(new Date().getTime());
                    FileUtil.writeFile(torHiddenService.privateKey.getBytes(), privKeyFile.getAbsolutePath());
                    FileUtil.writeFile(torHiddenService.toJSON().getBytes(), hiddenServiceFile.getAbsolutePath());

                    // Make sure torrc file is up to date
//                    List<String> torrcLines = FileUtil.readLines(torhsFile);
//                    boolean hsDirConfigured = false;
//                    boolean hsPortConfigured = false;
//                    boolean nextLine = false;
//                    String lineToRemove = null;
//                    for(String line : torrcLines) {
//                        if(!hsDirConfigured && line.equals("HiddenServiceDir "+hiddenServiceDir)) {
//                            hsDirConfigured = true;
//                            nextLine = true;
//                        }
//                        if(!hsPortConfigured && line.equals("HiddenServicePort "+ torhs.virtualPort+" 127.0.0.1:"+torhs.targetPort)) {
//                            hsPortConfigured = true;
//                        } else if(nextLine) {
//                            // Port config after our hidden service directory is old so mark for removal
//                            lineToRemove = line;
//                        }
//                    }
//                    if(!hsDirConfigured || !hsPortConfigured) {
//                        String torrcBody = new String(FileUtil.readFile(torrcFile.getAbsolutePath()));
//                        if(!hsDirConfigured)
//                            torrcBody += "\nHiddenServiceDir "+hiddenServiceDir+"\n";
//                        if(!hsPortConfigured)
//                            torrcBody += "\nHiddenServicePort "+ torhs.virtualPort+" 127.0.0.1:"+torhs.targetPort+"\n";
//                        FileUtil.writeFile(torrcBody.getBytes(), torrcFile.getAbsolutePath());
//                    }

                } else {
                    LOG.severe("Unable to create new TOR hidden service.");
                    updateStatus(ServiceStatus.ERROR);
                    updateNetworkStatus(NetworkStatus.ERROR);
                    return false;
                }
            } else if(launch("TORHS, API, localhost, " + torHiddenService.targetPort + ", " + handlerClass)) {
                if(controlConnection.isHSAvailable(torHiddenService.serviceId)) {
                    LOG.info("TOR Hidden Service available: "+ torHiddenService.serviceId
                            + " on virtualPort: "+ torHiddenService.virtualPort
                            + " to targetPort: "+ torHiddenService.targetPort);
                } else {
                    LOG.info("TOR Hidden Service not available; creating: "+ torHiddenService.serviceId);
                    torHiddenService = controlConnection.createHiddenService(torHiddenService.virtualPort, torHiddenService.targetPort, torHiddenService.privateKey);
                    LOG.info("TOR Hidden Service created: " + torHiddenService.serviceId
                            + " on virtualPort: " + torHiddenService.virtualPort
                            + " to targetPort: " + torHiddenService.targetPort);
                }
                getNetworkState().localPeer.getDid().getPublicKey().setAddress(torHiddenService.serviceId);
                getNetworkState().targetPort = torHiddenService.targetPort;
                getNetworkState().virtualPort = torHiddenService.virtualPort;
            } else {
                LOG.severe("Unable to launch TOR hidden service.");
                updateStatus(ServiceStatus.ERROR);
                updateNetworkStatus(NetworkStatus.ERROR);
                return false;
            }
        } catch (IOException e) {
            if(e.getLocalizedMessage().contains("Connection refused")) {
                LOG.info("Connection refused. TOR may not be installed and/or running. To install follow README.md in io/onemfive/network/sensors/tor package.");

            } else {
                LOG.warning(e.getLocalizedMessage());
            }
            updateStatus(ServiceStatus.ERROR);
            updateNetworkStatus(NetworkStatus.ERROR);
            return false;
        } catch (NoSuchAlgorithmException e) {
            LOG.warning("TORAlgorithm not supported: "+e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            updateNetworkStatus(NetworkStatus.ERROR);
            return false;
        }
        updateStatus(ServiceStatus.RUNNING);
//        kickOffDiscovery();
        return true;
    }

    private void kickOffDiscovery() {
        // Start Discovery
//        discovery = new TORNetworkPeerDiscovery(taskRunner, this);
//        taskRunner.addTask(discovery);
//        taskRunnerThread = new Thread(taskRunner);
//        taskRunnerThread.setDaemon(true);
//        taskRunnerThread.setName(TORNetworkPeerDiscovery.class.getSimpleName());
//        taskRunnerThread.start();
    }

    private void stopDiscovery() {

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
