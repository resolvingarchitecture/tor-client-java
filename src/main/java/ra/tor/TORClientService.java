package ra.tor;

import ra.common.Envelope;
import ra.common.messaging.MessageProducer;
import ra.common.network.*;
import ra.common.service.ServiceStatus;
import ra.common.service.ServiceStatusObserver;

import ra.http.client.EnvelopeJSONDataHandler;
import ra.http.client.HTTPClientService;
import ra.util.Config;
import ra.util.FileUtil;
import ra.util.RandomUtil;
import ra.util.SystemSettings;

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

    private TORControlConnection controlConnection;
    private TORHS torhs = null;

    private File torUserHome;
    private File torConfigHome;
    private File torrcFile;
    private File privKeyFile;
    private File hiddenServiceDir;

    private File torhsFile;


    public TORClientService(MessageProducer producer, ServiceStatusObserver observer) {
        super(Network.Tor, producer, observer);
    }

    TORHS getTorhs() {
        return torhs;
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

        torhs = new TORHS();

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

        torhsFile = new File(getServiceDirectory(), "torhs");
        if(torhsFile.exists()) {
            try {
                String json = new String(FileUtil.readFile(torhsFile.getAbsolutePath()));
                torhs.fromJSON(json);
            } catch (IOException e) {
                LOG.severe(e.getLocalizedMessage());
                return false;
            }
        }

        boolean destroyHiddenService = "true".equals(config.getProperty("ra.tor.privkey.destroy"));
        if(destroyHiddenService && privKeyFile.exists()) {
            LOG.info("Destroying Hidden Service....");
            privKeyFile.delete();
        } else if(privKeyFile.exists()) {
            LOG.info("Tor Hidden Service key found, loading...");
            byte[] bytes = null;
            try {
                bytes = FileUtil.readFile(privKeyFile.getAbsolutePath());
            } catch (IOException e) {
                LOG.warning(e.getLocalizedMessage());
                // Ensure private key is removed
                privKeyFile.delete();
            }
            if(bytes!=null) {
                torhs.privateKey = new String(bytes);
            }
            if(torhs.virtualPort==null || torhs.targetPort==null || torhs.serviceId==null || torhs.privateKey==null) {
                // Probably corrupted file
                LOG.info("Tor key found but likely corrupted, deleting....");
                privKeyFile.delete();
            }
        }
        updateStatus(ServiceStatus.STARTING);
        try {
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
            controlConnection.setEventHandler(new TOREventHandler(torhs, LOG));
            controlConnection.setEvents(Arrays.asList("CIRC", "ORCONN", "INFO", "NOTICE", "WARN", "ERR", "HS_DESC", "HS_DESC_CONTENT"));

            if(torhs.serviceId==null) {
                // Private key file doesn't exist, was unreadable, or requested to be destroyed so create a new hidden service
                privKeyFile = new File(hiddenServiceDir, "private_key");
                int virtPort;
                if(config.getProperty("ra.tor.virtualPort")==null) {
                    virtPort = randomTORPort();
                } else {
                    virtPort = Integer.parseInt(config.getProperty("ra.tor.virtualPort"));
                }
                int targetPort;
                if(config.getProperty("ra.tor.targetPort")==null) {
                    targetPort = randomTORPort();
                } else {
                    targetPort = Integer.parseInt(config.getProperty("ra.tor.targetPort"));
                }
                if(launch("TORHS, API, localhost, " + targetPort + ", " + EnvelopeJSONDataHandler.class.getName())) {
                    torhs = controlConnection.createHiddenService(virtPort, targetPort);
                    LOG.info("TOR Hidden Service Created: " + torhs.serviceId
                            + " on virtualPort: " + torhs.virtualPort
                            + " to targetPort: " + torhs.targetPort);
//                controlConnection.destroyHiddenService(hiddenService.serviceID);
//                hiddenService = controlConnection.createHiddenService(hiddenService.port, hiddenService.privateKey);
//                LOG.info("TOR Hidden Service Created: " + hiddenService.serviceID + " on port: "+hiddenService.port);
                    // Now save the private key
                    if (!privKeyFile.exists() && !privKeyFile.createNewFile()) {
                        LOG.warning("Unable to create file: " + privKeyFile.getAbsolutePath());
                        return false;
                    }
                    torhs.readable(true);
                    torhs.setCreatedAt(new Date().getTime());
                    FileUtil.writeFile(torhs.privateKey.getBytes(), privKeyFile.getAbsolutePath());
                    FileUtil.writeFile(torhs.toJSON().getBytes(), torhsFile.getAbsolutePath());

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
                    return  false;
                }
            } else if(launch("TORHS, API, localhost, " + torhs.targetPort + ", " + EnvelopeJSONDataHandler.class.getName())) {
                if(controlConnection.isHSAvailable(torhs.serviceId)) {
                    LOG.info("TOR Hidden Service available: "+torhs.serviceId
                            + " on virtualPort: "+torhs.virtualPort
                            + " to targetPort: "+torhs.targetPort);
                } else {
                    LOG.info("TOR Hidden Service not available; creating: "+torhs.serviceId);
                    torhs = controlConnection.createHiddenService(torhs.virtualPort, torhs.targetPort, torhs.privateKey);
                    LOG.info("TOR Hidden Service created: " + torhs.serviceId
                            + " on virtualPort: " + torhs.virtualPort
                            + " to targetPort: " + torhs.targetPort);
                }
            } else {
                LOG.severe("Unable to launch TOR hidden service.");
                updateStatus(ServiceStatus.ERROR);
                return false;
            }
        } catch (IOException e) {
            if(e.getLocalizedMessage().contains("Connection refused")) {
                LOG.info("Connection refused. TOR may not be installed and/or running. To install follow README.md in io/onemfive/network/sensors/tor package.");

            } else {
                LOG.warning(e.getLocalizedMessage());
            }
            updateStatus(ServiceStatus.ERROR);
            return false;
        } catch (NoSuchAlgorithmException e) {
            LOG.warning("TORAlgorithm not supported: "+e.getLocalizedMessage());
            updateStatus(ServiceStatus.ERROR);
            return false;
        }

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
