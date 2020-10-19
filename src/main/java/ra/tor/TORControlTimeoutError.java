package ra.tor;

import java.io.IOException;

/**
 * An exception raised when Tor tells us about an error.
 */
public class TORControlTimeoutError extends IOException {

    static final long serialVersionUID = 4;

    public TORControlTimeoutError(String s) {
        super(s);
    }
}
