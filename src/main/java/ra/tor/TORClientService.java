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
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.logging.Logger;

/**
 * Runs Tor <b>embedded</b>: the real, official Tor Project binary, downloaded once (verified
 * against a checksum pinned in {@link TorBinary}'s own source, never trusted from the network
 * alone), spawned and owned directly by this class via a plain {@link ProcessBuilder}, and
 * driven entirely over its control port using this repo's own {@link TORControlConnection} -
 * no system Tor daemon, no third-party embedding library, no Kotlin. See {@link EmbeddedTor}
 * and DESIGN.md "Embedded Tor" for the full rationale and trust model.
 *
 * <p>There is deliberately no code path anywhere in this class that looks for, or falls back
 * to, some other already-running Tor instance - the embedded process this class itself spawns
 * is the only one it ever uses.
 */
public final class TORClientService extends HTTPService {

    private static final Logger LOG = Logger.getLogger(TORClientService.class.getName());

    public static final String HOST = "127.0.0.1";
    /** {@link TorSocksRelay}'s own listening port - every consumer of this service's Tor
     *  connectivity connects here, never to the embedded process's own SOCKS port directly. */
    public static final Integer PORT_SOCKS_RELAY = 9052;

    private static final long EMBEDDED_TOR_TIMEOUT_MS = 120_000L;

    private final Map<String, NetworkClientSession> sessions = new HashMap<>();
    private Thread taskRunnerThread;
    private volatile TorSocksRelay socksRelay;
    private volatile EmbeddedTor embeddedTor;

    private TORControlConnection controlConnection;
    private TORHiddenService torHiddenService = null;

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

    /** The network this service carries traffic over. */
    public Network getNetwork() {
        return Network.Tor;
    }

    TORHiddenService getTorHiddenService() {
        return torHiddenService;
    }

    public int randomTORPort() {
        return RandomUtil.nextRandomInteger(10000, 65535);
    }

    /** {@code null} before the hidden service exists (start() never ran, failed, or hasn't reached that point yet). */
    public String getHiddenServiceId() {
        return torHiddenService != null ? torHiddenService.serviceId : null;
    }

    /** {@code null} under the same conditions as {@link #getHiddenServiceId()}. */
    public String getHiddenServiceURL() {
        String id = getHiddenServiceId();
        return id != null ? "http://" + id + ".onion" : null;
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

        LOG.info("Provisioning embedded Tor (downloads and verifies the official binary on first run only)...");
        updateNetworkStatus(NetworkStatus.CONNECTING);
        File torCacheDir = new File(SystemSettings.getUserHomeDir(), ".1m5" + File.separator + "tor-bin");
        File torDataDir = new File(getServiceDirectory(), "tor-data");
        EmbeddedTor tor = new EmbeddedTor(torDataDir);
        this.embeddedTor = tor; // assigned before start() so a failure partway through never leaks the spawned process - shutdown() below is always safe to call
        try {
            TorBinary.Provisioned bin = new TorBinary(torCacheDir).resolve();
            tor.start(bin, EMBEDDED_TOR_TIMEOUT_MS);
            this.controlConnection = tor.control();
        } catch (IOException e) {
            LOG.severe("Embedded Tor failed to start: " + e.getMessage());
            tor.shutdown();
            this.embeddedTor = null;
            updateNetworkStatus(NetworkStatus.DISCONNECTED);
            updateStatus(ServiceStatus.UNAVAILABLE);
            return false;
        }

        try {
            socksRelay = new TorSocksRelay(PORT_SOCKS_RELAY, HOST, embeddedTor.socksPort());
            socksRelay.start();
        } catch (IOException e) {
            LOG.severe("could not start TorSocksRelay on port " + PORT_SOCKS_RELAY + ": " + e.getMessage());
            embeddedTor.shutdown();
            updateStatus(ServiceStatus.ERROR);
            updateNetworkStatus(NetworkStatus.ERROR);
            return false;
        }

        // Through the relay, not the embedded process's own SOCKS port directly - so this
        // service's own outbound HTTP fetches (sendOut/fetchOverTor/OPERATION_SEND) pass through
        // the one path TorSocksRelay's egress-outcome tracking observes, same as every other
        // consumer of this node's Tor connectivity.
        proxy = new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(HOST, PORT_SOCKS_RELAY));

        LOG.info("Starting underlying HTTP Service...");
        try {
            super.start(config);
        } catch (Throwable t) {
            LOG.severe("super.start(config) (underlying HTTP Service) threw: " + t);
            return false;
        }

        LOG.info("Initializing TOR Hidden Service...");
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
            LOG.warning(e.getLocalizedMessage());
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

    /** The local SOCKS relay every consumer of this Tor connection should use - null until {@link #start} succeeds. */
    public TorSocksRelay socksRelay() {
        return socksRelay;
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
        if (socksRelay != null) { socksRelay.shutdown(); socksRelay = null; }
        if (embeddedTor != null) { embeddedTor.shutdown(); embeddedTor = null; }
        super.shutdown();
        updateStatus(ServiceStatus.SHUTDOWN);
        return true;
    }

    @Override
    public boolean gracefulShutdown() {
        updateStatus(ServiceStatus.GRACEFULLY_SHUTTING_DOWN);
        if (socksRelay != null) { socksRelay.shutdown(); socksRelay = null; }
        if (embeddedTor != null) { embeddedTor.shutdown(); embeddedTor = null; }
        super.gracefulShutdown();
        updateStatus(ServiceStatus.GRACEFULLY_SHUTDOWN);
        return true;
    }
}
