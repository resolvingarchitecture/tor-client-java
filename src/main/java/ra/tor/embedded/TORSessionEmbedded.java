package ra.tor.embedded;


import java.util.logging.Logger;


public class TORSessionEmbedded extends ClearnetSession {

    private static final Logger LOG = Logger.getLogger(TORSessionEmbedded.class.getName());

    private io.onemfive.network.sensors.tor.TOR tor;

    public TORSessionEmbedded(io.onemfive.network.sensors.tor.TOR tor) {
        super(tor);
        this.tor = tor;
    }

    @Override
    public Boolean send(NetworkPacket packet) {
        LOG.warning("Not yet implemented.");
        return null;
    }

    @Override
    public boolean open(String address) {
        LOG.warning("Not yet implemented.");
        return false;
    }

    @Override
    public boolean connect() {
        LOG.warning("Not yet implemented.");
        return false;
    }

    @Override
    public boolean disconnect() {
        LOG.warning("Not yet implemented.");
        return false;
    }

    @Override
    public boolean isConnected() {
        LOG.warning("Not yet implemented.");
        return false;
    }

    @Override
    public boolean close() {
        LOG.warning("Not yet implemented.");
        return false;
    }
}
