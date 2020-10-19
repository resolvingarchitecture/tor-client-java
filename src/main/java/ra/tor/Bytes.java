package ra.tor;

import java.util.Arrays;
import java.util.List;

/**
 * Static class to do bytewise structure manipulation in Java.
 */
final class Bytes {

    /**
     * Read bytes from 'ba' starting at 'pos', dividing them into strings
     * along the character in 'split' and writing them into 'lst'
     */
    public static List<String> splitStr(List<String> lst, String str) {
        // split string on spaces, include trailing/leading
        String[] tokenArray = str.split(" ", -1);
        if (lst == null) {
            lst = Arrays.asList( tokenArray );
        } else {
            lst.addAll( Arrays.asList( tokenArray ) );
        }
        return lst;
    }

    private static final char[] NYBBLES = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    public static final String hex(byte[] ba) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < ba.length; ++i) {
            int b = (ba[i]) & 0xff;
            buf.append(NYBBLES[b >> 4]);
            buf.append(NYBBLES[b&0x0f]);
        }
        return buf.toString();
    }

    private Bytes() {};
}
