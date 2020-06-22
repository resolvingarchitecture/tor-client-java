package ra.tor.local.control;

import java.io.IOException;

/**
 * An exception raised when Tor behaves in an unexpected way.
 */
public class TORControlSyntaxError extends IOException {

    static final long serialVersionUID = 3;

    public TORControlSyntaxError(String s) { super(s); }
}
