package ra.tor.local.control;

import java.util.Iterator;
import java.util.logging.Logger;

public class DebuggingEventHandler implements EventHandler {

    private final Logger out;

    public DebuggingEventHandler(Logger LOG) {
        out = LOG;
    }

    public void circuitStatus(String status, String circID, String path) {
        out.fine("Circuit "+circID+" is now "+status+" (path="+path+")");
    }
    public void streamStatus(String status, String streamID, String target) {
        out.fine("Stream "+streamID+" is now "+status+" (target="+target+")");
    }
    public void orConnStatus(String status, String orName) {
        out.fine("OR connection to "+orName+" is now "+status);
    }
    public void bandwidthUsed(long read, long written) {
        out.fine("Bandwidth usage: "+read+" bytes read; "+ written+" bytes written.");
    }
    public void newDescriptors(java.util.List<String> orList) {
        out.fine("New descriptors for routers:");
        for (Iterator<String> i = orList.iterator(); i.hasNext(); )
            out.fine("   "+i.next());
    }
    public void message(String type, String msg) {
        out.fine("["+type+"] "+msg.trim());
    }

    public void hiddenServiceEvent(String type, String msg) {
        out.fine("hiddenServiceEvent: HS_DESC " + msg.trim());
    }

    public void hiddenServiceFailedEvent(String reason, String msg) {
        out.fine("hiddenServiceEvent: HS_DESC " + msg.trim());
    }

    public void hiddenServiceDescriptor(String descriptorId, String descriptor, String msg) {
        out.fine("hiddenServiceEvent: HS_DESC_CONTENT " + msg.trim());
    }

    public void unrecognized(String type, String msg) {
        out.fine("unrecognized event ["+type+"] "+msg.trim());
    }

    @Override
    public void timeout() {
        out.warning("The control connection to tor did not provide a response within one minute of waiting.");
    }

}
