package ra.tor;

/**
 * supported algorithms according to
 * https://github.com/torproject/torspec/raw/4421149986369b4f746fc02a5d78c7337fe5d4ea/control-spec.txt
 */
public class TORAlgorithms {
    public static final String RSA1024 = "RSA1024";
    public static final String ED25519V3 = "ED25519-V3";

    public static String[] toArray() {
        return new String[]{
                TORAlgorithms.RSA1024,
                TORAlgorithms.ED25519V3
        };
    }
}
