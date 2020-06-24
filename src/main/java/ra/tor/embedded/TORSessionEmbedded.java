package ra.tor.embedded;


import ra.common.network.NetworkPacket;

import java.util.logging.Logger;


public class TORSessionEmbedded extends HTTPSession {

    private static final Logger LOG = Logger.getLogger(TORSessionEmbedded.class.getName());



    public Boolean send(NetworkPacket packet) {
        LOG.warning("Not yet implemented.");
        return null;
    }

    public boolean open(String address) {
        LOG.warning("Not yet implemented.");
        return false;
    }

    public boolean connect() {
        LOG.warning("Not yet implemented.");
        return false;
    }

    public boolean disconnect() {
        LOG.warning("Not yet implemented.");
        return false;
    }

    public boolean isConnected() {
        LOG.warning("Not yet implemented.");
        return false;
    }

    public boolean close() {
        LOG.warning("Not yet implemented.");
        return false;
    }
}
