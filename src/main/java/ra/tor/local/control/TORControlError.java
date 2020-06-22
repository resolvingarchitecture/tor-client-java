package ra.tor.local.control;

import java.io.IOException;

/**
 * An exception raised when Tor tells us about an error.
 */
public class TORControlError extends IOException {

    static final long serialVersionUID = 3;

    private final int errorType;

    public TORControlError(int type, String s) {
        super(s);
        errorType = type;
    }

    public TORControlError(String s) {
        this(-1, s);
    }

    public int getErrorType() {
        return errorType;
    }

    public String getErrorMsg() {
        try {
            if (errorType == -1)
                return null;
            return TORControlCommands.ERROR_MSGS[errorType];
        } catch (ArrayIndexOutOfBoundsException ex) {
            return "Unrecongized error #"+errorType;
        }
    }
}
