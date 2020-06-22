package ra.tor.local;

import ra.tor.TORHiddenService;
import ra.tor.local.control.DebuggingEventHandler;
import ra.tor.local.control.TORControlConnection;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.logging.Logger;

public class TORSensorSessionLocal extends HTTPClientSession {

    private static final Logger LOG = Logger.getLogger(TORSensorSessionLocal.class.getName());

    public static final String HOST = "127.0.0.1";
    public static final Integer PORT_SOCKS = 9050;
    public static final Integer PORT_CONTROL = 9051;
//    public static final Integer PORT_CONTROL = 9100;
    public static final Integer PORT_HIDDEN_SERVICE = 9151;

    private TORControlConnection controlConnection;
    private io.onemfive.network.sensors.tor.TOR sensor;
    private TORHiddenService hiddenService = null;

    public TORSensorSessionLocal(io.onemfive.network.sensors.tor.TOR tor) {
        super(tor, new Proxy(Proxy.Type.SOCKS, new InetSocketAddress(HOST, PORT_SOCKS)));
        this.sensor = tor;
        clientsEnabled = true;
        serverEnabled = true;
    }

    @Override
    public boolean init(Properties properties) {
        this.properties = properties;
        // read the local TOR address key from the address file if it exists
        String torSensorDir = properties.getProperty("1m5.dir.sensors.tor");
        File privKeyFile = new File(torSensorDir, "private_key");
        FileReader fileReader = null;
        boolean destroyHiddenService = false;
        try {
            fileReader = new FileReader(privKeyFile);
            char[] addressBuffer = new char[(int)privKeyFile.length()];
            fileReader.read(addressBuffer);
            String jsonPrivKey = new String(addressBuffer);
            hiddenService = new TORHiddenService();
            hiddenService.fromJSON(jsonPrivKey);
            if(hiddenService.virtualPort==null) {
                destroyHiddenService = true;
            }
        } catch (IOException e) {
            LOG.info("Private key file doesn't exist or isn't readable." + e);
        } catch (Exception e) {
            // Won't happen, inputStream != null
            LOG.warning(e.getLocalizedMessage());
        } finally {
            if (fileReader != null) {
                try {
                    fileReader.close();
                } catch (IOException e) {
                    LOG.warning("Error closing file: " + privKeyFile.getAbsolutePath() + ": " + e);
                }
            }
        }
        try {
            controlConnection = getControlConnection();
//                Map<String, String> m = conn.getInfo(Arrays.asList("stream-status", "orconn-status", "circuit-status", "version"));
            Map<String, String> m = controlConnection.getInfo(Arrays.asList("version"));
            StringBuilder sb = new StringBuilder();
            sb.append("TOR config:");
            for (Iterator<Map.Entry<String, String>> i = m.entrySet().iterator(); i.hasNext(); ) {
                Map.Entry<String, String> e = i.next();
                sb.append("\n\t"+e.getKey()+"="+e.getValue());
            }
            LOG.info(sb.toString());
            controlConnection.setEventHandler(new DebuggingEventHandler(LOG));
            controlConnection.setEvents(Arrays.asList("EXTENDED", "CIRC", "ORCONN", "INFO", "NOTICE", "WARN", "ERR", "HS_DESC", "HS_DESC_CONTENT"));
            if(destroyHiddenService) {
                controlConnection.destroyHiddenService(hiddenService.serviceID);
                hiddenService = null;
                privKeyFile.delete();
                privKeyFile = new File(torSensorDir, "private_key");
            }
            if(hiddenService==null) {
                // Private key file doesn't exist, is unreadable, or didn't have a virtual port so create a new hidden service
                int virtPort = TORHiddenService.randomTORPort();
                int targetPort = TORHiddenService.randomTORPort();
                hiddenService = controlConnection.createHiddenService(virtPort, targetPort);
                LOG.info("TOR Hidden Service Created: " + hiddenService.serviceID + " on virtualPort: "+hiddenService.virtualPort+" to targetPort: "+hiddenService.targetPort);
//                controlConnection.destroyHiddenService(hiddenService.serviceID);
//                hiddenService = controlConnection.createHiddenService(hiddenService.port, hiddenService.privateKey);
//                LOG.info("TOR Hidden Service Created: " + hiddenService.serviceID + " on port: "+hiddenService.port);
                // Now save the private key
                if(!privKeyFile.exists() && !privKeyFile.createNewFile()) {
                    LOG.warning("Unable to create file: "+privKeyFile.getAbsolutePath());
                    return false;
                }
                FileUtil.writeFile(hiddenService.toJSON().getBytes(), privKeyFile.getAbsolutePath());
            } else {
                if(controlConnection.isHSAvailable(hiddenService.serviceID)) {
                    LOG.info("TOR Hidden Service available: "+hiddenService.serviceID + " on virtualPort: "+hiddenService.virtualPort+" to targetPort: "+hiddenService.targetPort);
                } else {
                    LOG.info("TOR Hidden Service not available; creating: "+hiddenService.serviceID);
                    hiddenService = controlConnection.createHiddenService(hiddenService.virtualPort, hiddenService.targetPort, hiddenService.privateKey);
                    LOG.info("TOR Hidden Service created: " + hiddenService.serviceID+ " on virtualPort: "+hiddenService.virtualPort+" to targetPort: "+hiddenService.targetPort);
                }
            }
        } catch (IOException e) {
            if(e.getLocalizedMessage().contains("Connection refused")) {
                LOG.info("Connection refused. TOR may not be installed and/or running. To install follow README.md in io/onemfive/network/sensors/tor package.");
                sensor.updateStatus(SensorStatus.NETWORK_UNAVAILABLE);
            } else {
                LOG.warning(e.getLocalizedMessage());
            }
            return false;
        } catch (NoSuchAlgorithmException e) {
            LOG.warning("TORAlgorithm not supported: "+e.getLocalizedMessage());
            return false;
        }
        NetworkNode localNode = sensor.getSensorManager().getPeerManager().getLocalNode();
        NetworkPeer localTORPeer;
        if(localNode.getNetworkPeer(Network.TOR)!=null) {
            localTORPeer = localNode.getNetworkPeer(Network.TOR);
        } else {
            localTORPeer = new NetworkPeer(Network.TOR, localNode.getNetworkPeer().getDid().getUsername(), localNode.getNetworkPeer().getDid().getPassphrase());
            localNode.addNetworkPeer(localTORPeer);
        }
        sensor.getNetworkState().virtualPort = hiddenService.virtualPort;
        sensor.getNetworkState().targetPort = hiddenService.targetPort;
        while(localNode.getNetworkPeer().getId()==null) {
            Wait.aMs(100);
        }
        localTORPeer.setId(localNode.getNetworkPeer().getId());
        localTORPeer.setPort(hiddenService.virtualPort);
        localTORPeer.getDid().getPublicKey().setFingerprint(hiddenService.serviceID); // used as key
        localTORPeer.getDid().getPublicKey().setAddress(hiddenService.serviceID);
        sensor.getNetworkState().localPeer = localTORPeer;
        sensor.getSensorManager().getPeerManager().savePeer(localTORPeer, true);
        sensor.updateModelListeners();
        // Setup params for server creation to back hidden service
        params = new String[]{"1M5-TORHiddenService","hiddenService",String.valueOf(hiddenService.targetPort)};
        return true;
    }

    @Override
    public Boolean send(NetworkPacket packet) {
        LOG.info("Tor Sensor sending packet...");
        if (packet == null) {
            LOG.warning("No Packet.");
            return false;
        }
        if (packet.getToPeer() == null) {
            LOG.warning("No Peer for TOR found in toDID while sending to TOR.");
            packet.statusCode = NetworkPacket.DESTINATION_PEER_REQUIRED;
            return false;
        }
        if (packet.getToPeer().getNetwork() != Network.TOR) {
            LOG.warning("Not a packet for TOR.");
            packet.statusCode = NetworkPacket.DESTINATION_PEER_WRONG_NETWORK;
            return false;
        }
        if (packet.getToPeer().getPort() == null) {
            LOG.warning("No To Port for TOR found in toDID while sending to TOR.");
            packet.statusCode = NetworkPacket.NO_PORT;
            return false;
        }
        if (packet.getToPeer().getDid().getPublicKey().getAddress() == null) {
            LOG.warning("No To Address for TOR found in toDID while sending to TOR.");
            packet.statusCode = NetworkPacket.NO_ADDRESS;
            return false;
        }
        try {
            URL url = new URL("http://"+packet.getToPeer().getDid().getPublicKey().getAddress()+":"+packet.getToPeer().getPort());
            packet.getEnvelope().setURL(url);
            String content = packet.toJSON();
            DLC.addContent(content, packet.getEnvelope());
            LOG.info("Content to send: " + content);
            if(!super.send(packet)) {
                handleFailure(packet.getEnvelope().getMessage());
                return false;
            }
        } catch (MalformedURLException e) {
            LOG.warning(e.getLocalizedMessage());
            return false;
        }
        return true;
    }

    private TORControlConnection getControlConnection() throws IOException {
        Socket s = new Socket("127.0.0.1", PORT_CONTROL);
        TORControlConnection conn = new TORControlConnection(s);
        conn.authenticate(new byte[0]);
        return conn;
    }

    public void get(URL url) {
        // Get URL
        Request request = new Request();
        Envelope envelope = Envelope.documentFactory();
        envelope.setURL(url);
        envelope.setAction(Envelope.Action.GET);
        request.setEnvelope(envelope);
        if(send(request)) {
            byte[] content = (byte[]) DLC.getContent(envelope);
            LOG.info("Content length: "+content.length);
            LOG.info("Content: "+new String(content));
        }
    }

    protected void handleFailure(Message m) {
        if(m!=null && m.getErrorMessages()!=null && m.getErrorMessages().size()>0) {
            boolean blocked = false;
            for (String err : m.getErrorMessages()) {
                LOG.warning("HTTP Error Message (Tor): " + err);
                if(!blocked) {
                    switch (err) {
                        case "403": {
                            // Forbidden
                            LOG.info("Received HTTP 403 response (Tor): Forbidden. Tor Sensor considered blocked.");
                            sensor.updateStatus(SensorStatus.NETWORK_BLOCKED);
                            blocked = true;
                            break;
                        }
                        case "408": {
                            // Request Timeout
                            LOG.info("Received HTTP 408 response (Tor): Request Timeout. Tor Sensor considered blocked.");
                            sensor.updateStatus(SensorStatus.NETWORK_BLOCKED);
                            blocked = true;
                            break;
                        }
                        case "410": {
                            // Gone
                            LOG.info("Received HTTP 410 response (Tor): Gone. Tor Sensor considered blocked.");
                            sensor.updateStatus(SensorStatus.NETWORK_BLOCKED);
                            blocked = true;
                            break;
                        }
                        case "418": {
                            // I'm a teapot
                            LOG.warning("Received HTTP 418 response (Tor): I'm a teapot. Tor Sensor ignoring.");
                            break;
                        }
                        case "451": {
                            // Unavailable for legal reasons; your IP address might be denied access to the resource
                            LOG.info("Received HTTP 451 response (Tor): unavailable for legal reasons. Tor Sensor considered blocked.");
                            // Notify Sensor Manager Tor is getting blocked
                            sensor.updateStatus(SensorStatus.NETWORK_BLOCKED);
                            blocked = true;
                            break;
                        }
                        case "511": {
                            // Network Authentication Required
                            LOG.info("Received HTTP511 response (Tor): network authentication required. Tor Sensor considered blocked.");
                            sensor.updateStatus(SensorStatus.NETWORK_BLOCKED);
                            blocked = true;
                            break;
                        }
                    }
                }
            }
        }
    }

//    public static void main(String[] args) {
//        Properties p = new Properties();
//        p.setProperty("1m5.dir.sensors","/home/objectorange/1m5/platform/services/io.onemfive.network.NetworkService/sensors");
//        SimpleTorSensor s = new SimpleTorSensor();
//        s.start(p);
//        try {
//            URL duckduckGoOnion = new URL("https://3g2upl4pq6kufc4m.onion/");
//            s.get(duckduckGoOnion);
//        } catch (MalformedURLException e) {
//            System.out.println(e.getLocalizedMessage());
//        }

//        try {
//            TorControlConnection conn = getConnection(args);
//            Map<String,String> m = conn.getInfo(Arrays.asList("stream-status","orconn-status","circuit-status","version"));
//            for (Iterator<Map.Entry<String, String>> i = m.entrySet().iterator(); i.hasNext(); ) {
//                Map.Entry<String,String> e = i.next();
//                System.out.println("KEY: "+e.getKey());
//                System.out.println("VAL: "+e.getValue());
//            }
//
//            conn.setEventHandler(new DebuggingEventHandler(LOG));
//            conn.setEvents(Arrays.asList("EXTENDED", "CIRC", "ORCONN", "INFO", "NOTICE", "WARN", "ERR", "HS_DESC", "HS_DESC_CONTENT" ));
//            TorControlConnection.CreateHiddenServiceResult result = conn.createHiddenService(10026);
//            System.out.println("ServiceID: "+result.serviceID);
//            System.out.println("PrivateKey: "+result.privateKey);
//            conn.destroyHiddenService(result.serviceID);
//            result = conn.createHiddenService(10026, result.privateKey);
//            System.out.println("ServiceID: "+result.serviceID);
//            System.out.println("PrivateKey: "+result.privateKey);
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
}
