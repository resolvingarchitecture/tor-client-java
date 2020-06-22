package ra.tor.local.control;

public interface TORControlCommands {

    short CMD_ERROR = 0x0000;
    short CMD_DONE = 0x0001;
    short CMD_SETCONF = 0x0002;
    short CMD_GETCONF = 0x0003;
    short CMD_CONFVALUE = 0x0004;
    short CMD_SETEVENTS = 0x0005;
    short CMD_EVENT = 0x0006;
    short CMD_AUTH = 0x0007;
    short CMD_SAVECONF = 0x0008;
    short CMD_SIGNAL = 0x0009;
    short CMD_MAPADDRESS = 0x000A;
    short CMD_GETINFO = 0x000B;
    short CMD_INFOVALUE = 0x000C;
    short CMD_EXTENDCIRCUIT = 0x000D;
    short CMD_ATTACHSTREAM = 0x000E;
    short CMD_POSTDESCRIPTOR = 0x000F;
    short CMD_FRAGMENTHEADER = 0x0010;
    short CMD_FRAGMENT = 0x0011;
    short CMD_REDIRECTSTREAM = 0x0012;
    short CMD_CLOSESTREAM = 0x0013;
    short CMD_CLOSECIRCUIT = 0x0014;

    String[] CMD_NAMES = {
            "ERROR",
            "DONE",
            "SETCONF",
            "GETCONF",
            "CONFVALUE",
            "SETEVENTS",
            "EVENT",
            "AUTH",
            "SAVECONF",
            "SIGNAL",
            "MAPADDRESS",
            "GETINFO",
            "INFOVALUE",
            "EXTENDCIRCUIT",
            "ATTACHSTREAM",
            "POSTDESCRIPTOR",
            "FRAGMENTHEADER",
            "FRAGMENT",
            "REDIRECTSTREAM",
            "CLOSESTREAM",
            "CLOSECIRCUIT",
    };

    short EVENT_CIRCSTATUS = 0x0001;
    short EVENT_STREAMSTATUS = 0x0002;
    short EVENT_ORCONNSTATUS = 0x0003;
    short EVENT_BANDWIDTH = 0x0004;
    short EVENT_NEWDESCRIPTOR = 0x0006;
    short EVENT_MSG_DEBUG = 0x0007;
    short EVENT_MSG_INFO = 0x0008;
    short EVENT_MSG_NOTICE = 0x0009;
    short EVENT_MSG_WARN = 0x000A;
    short EVENT_MSG_ERROR = 0x000B;

    String[] EVENT_NAMES = {
            "(0)",
            "CIRC",
            "STREAM",
            "ORCONN",
            "BW",
            "OLDLOG",
            "NEWDESC",
            "DEBUG",
            "INFO",
            "NOTICE",
            "WARN",
            "ERR",
    };

    byte CIRC_STATUS_LAUNCHED = 0x01;
    byte CIRC_STATUS_BUILT = 0x02;
    byte CIRC_STATUS_EXTENDED = 0x03;
    byte CIRC_STATUS_FAILED = 0x04;
    byte CIRC_STATUS_CLOSED = 0x05;

    String[] CIRC_STATUS_NAMES = {
            "LAUNCHED",
            "BUILT",
            "EXTENDED",
            "FAILED",
            "CLOSED",
    };

    byte STREAM_STATUS_SENT_CONNECT = 0x00;
    byte STREAM_STATUS_SENT_RESOLVE = 0x01;
    byte STREAM_STATUS_SUCCEEDED = 0x02;
    byte STREAM_STATUS_FAILED = 0x03;
    byte STREAM_STATUS_CLOSED = 0x04;
    byte STREAM_STATUS_NEW_CONNECT = 0x05;
    byte STREAM_STATUS_NEW_RESOLVE = 0x06;
    byte STREAM_STATUS_DETACHED = 0x07;

    String[] STREAM_STATUS_NAMES = {
            "SENT_CONNECT",
            "SENT_RESOLVE",
            "SUCCEEDED",
            "FAILED",
            "CLOSED",
            "NEW_CONNECT",
            "NEW_RESOLVE",
            "DETACHED"
    };

    byte OR_CONN_STATUS_LAUNCHED = 0x00;
    byte OR_CONN_STATUS_CONNECTED = 0x01;
    byte OR_CONN_STATUS_FAILED = 0x02;
    byte OR_CONN_STATUS_CLOSED = 0x03;

    String[] OR_CONN_STATUS_NAMES = {
            "LAUNCHED","CONNECTED","FAILED","CLOSED"
    };

    byte SIGNAL_HUP = 0x01;
    byte SIGNAL_INT = 0x02;
    byte SIGNAL_USR1 = 0x0A;
    byte SIGNAL_USR2 = 0x0C;
    byte SIGNAL_TERM = 0x0F;

    String ERROR_MSGS[] = {
            "Unspecified error",
            "Internal error",
            "Unrecognized message type",
            "Syntax error",
            "Unrecognized configuration key",
            "Invalid configuration value",
            "Unrecognized byte code",
            "Unauthorized",
            "Failed authentication attempt",
            "Resource exhausted",
            "No such stream",
            "No such circuit",
            "No such OR",
    };
}
