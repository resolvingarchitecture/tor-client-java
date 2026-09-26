package ra.tor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Provisions the official Tor Project binary - the same "Expert Bundle" Tor Browser itself
 * ships - for the current desktop platform: downloaded once into a local cache, verified
 * against a SHA-256 pinned in this class's own source, then reused on every later start.
 * No system Tor daemon, no third-party embedding library, no Kotlin.
 *
 * <p><b>Why the checksum is pinned here, not fetched alongside the download:</b> Tor Project
 * also publishes a signed {@code sha256sums-signed-build.txt} next to every release, but
 * trusting a checksum fetched from the same channel as the file it checks is circular - an
 * attacker able to serve a tampered binary over that channel could serve a matching tampered
 * checksum too. The values below were copied in only after verifying that sums file's PGP
 * signature against the Tor Browser Developers signing key (fingerprint
 * {@code EF6E286DDA85EA2A4BA7DE684E2C6E8793298290}) on 2026-09-26; from that point on, this
 * source file - reviewed and version-controlled like any other code - is the actual trust
 * anchor, not the network. Re-verify the same way before bumping {@link #TOR_VERSION}.
 *
 * <p><b>Android is deliberately not covered here</b> even though the Tor Project publishes
 * Android expert bundles too: Android blocks executing a binary extracted into app-writable
 * storage (W^X on API 29+), so an Android consumer must instead package the binary as
 * {@code jniLibs/<abi>/libtor.so} at APK-build time and hand this class's sibling {@link
 * EmbeddedTor} an already-executable path directly - see 1m5-remnant's {@code :transport-tor}.
 *
 * <p>This class is not a substitute for independent security review before this library is
 * relied on anywhere privacy failure has real consequences - see DESIGN.md "Embedded Tor".
 */
public final class TorBinary {

    private static final Logger LOG = Logger.getLogger(TorBinary.class.getName());

    static final String TOR_VERSION = "15.0.23";
    private static final String DIST_BASE = "https://dist.torproject.org/torbrowser/" + TOR_VERSION + "/";

    private enum Platform {
        LINUX_X86_64("linux-x86_64", "08d49de27f542b8f73e2014e064d8320562b5d20019c03d4725c5a5249d97985"),
        LINUX_I686("linux-i686", "af684a8839d61778b5722938e43cc0c1cc9886f8fd8b7fb33d056077363edfba"),
        MACOS_X86_64("macos-x86_64", "be1be1cb13cd093713f02a0beade0d2471b61119011bfeb0efc08353eadf2e4e"),
        MACOS_AARCH64("macos-aarch64", "e8ea3f667c83309abad34280f0f9e1cfae52843da6b8db111ca15d6221051db5"),
        WINDOWS_X86_64("windows-x86_64", "231dad6b9cb401a54c260db7046965ef04e4f72ff071b140d423fb5da281ab1e"),
        WINDOWS_I686("windows-i686", "1e4de9a4f1d99b8f40b5e0c75f3dcc3ea51b0aeab040d48fd23881e9fa94979a");

        final String key;
        final String sha256;

        Platform(String key, String sha256) {
            this.key = key;
            this.sha256 = sha256;
        }

        String archiveName() {
            return "tor-expert-bundle-" + key + "-" + TOR_VERSION + ".tar.gz";
        }

        boolean windows() {
            return key.startsWith("windows");
        }
    }

    /**
     * Everything {@link EmbeddedTor} needs to spawn the process, once provisioning succeeds.
     * Public - and this constructor public - so a platform this class's own download/verify
     * logic doesn't cover (Android; see the class javadoc) can still hand {@link EmbeddedTor}
     * a binary it obtained its own way (e.g. a {@code libtor.so} packaged in {@code jniLibs}
     * and extracted by the OS installer) instead of one downloaded by {@link #resolve}.
     */
    public static final class Provisioned {
        public final File torExecutable;
        public final File libraryDir;
        public final File geoipFile;
        public final File geoip6File;

        public Provisioned(File torExecutable, File libraryDir, File geoipFile, File geoip6File) {
            this.torExecutable = torExecutable;
            this.libraryDir = libraryDir;
            this.geoipFile = geoipFile;
            this.geoip6File = geoip6File;
        }
    }

    private final File cacheRoot;

    TorBinary(File cacheRoot) {
        this.cacheRoot = cacheRoot;
    }

    /** Downloads (if not already cached and verified) and returns paths into the real Tor Project binary for this OS/arch. */
    Provisioned resolve() throws IOException {
        Platform platform = detectPlatform();
        File platformDir = new File(cacheRoot, TOR_VERSION + File.separator + platform.key);
        File verifiedMarker = new File(platformDir, ".verified-" + platform.sha256.substring(0, 12));
        File extractedRoot = new File(platformDir, "extracted");

        if (!verifiedMarker.exists()) {
            if (!platformDir.exists() && !platformDir.mkdirs()) {
                throw new IOException("could not create cache directory " + platformDir);
            }
            File archive = new File(platformDir, platform.archiveName());
            LOG.info("Downloading " + platform.archiveName() + " from the Tor Project (one-time)...");
            download(DIST_BASE + platform.archiveName(), archive);
            String actual = sha256(archive);
            if (!actual.equalsIgnoreCase(platform.sha256)) {
                archive.delete();
                throw new IOException("SHA-256 mismatch for " + platform.archiveName()
                        + " - expected " + platform.sha256 + " but got " + actual
                        + ". Refusing to use an unverified Tor binary.");
            }
            LOG.info("Checksum verified against the value pinned in TorBinary's own source.");
            deleteRecursive(extractedRoot);
            if (!extractedRoot.mkdirs()) {
                throw new IOException("could not create extraction directory " + extractedRoot);
            }
            extractTarGz(archive, extractedRoot);
            archive.delete();
            if (!verifiedMarker.createNewFile()) {
                throw new IOException("could not write verification marker at " + verifiedMarker);
            }
        }

        File torDir = new File(extractedRoot, "tor");
        File exe = new File(torDir, platform.windows() ? "tor.exe" : "tor");
        if (!exe.exists()) {
            throw new IOException("expected tor executable not found at " + exe + " after extraction");
        }
        exe.setExecutable(true, false);
        File dataDir = new File(extractedRoot, "data");
        return new Provisioned(exe, torDir, new File(dataDir, "geoip"), new File(dataDir, "geoip6"));
    }

    private static Platform detectPlatform() throws IOException {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
        boolean arm64 = arch.contains("aarch64") || arch.contains("arm64");
        boolean x86_64 = arch.contains("amd64") || arch.contains("x86_64");
        if (os.contains("linux")) {
            if (x86_64) return Platform.LINUX_X86_64;
            if (!arm64) return Platform.LINUX_I686;
            throw new IOException("no official Tor Project expert bundle for Linux/" + arch
                    + " - only linux-x86_64 and linux-i686 are published");
        }
        if (os.contains("mac") || os.contains("darwin")) {
            return arm64 ? Platform.MACOS_AARCH64 : Platform.MACOS_X86_64;
        }
        if (os.contains("win")) {
            return x86_64 ? Platform.WINDOWS_X86_64 : Platform.WINDOWS_I686;
        }
        throw new IOException("no known embedded-Tor binary for OS '" + os + "' (arch " + arch + ")");
    }

    private static void download(String url, File dest) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setInstanceFollowRedirects(true);
        conn.setConnectTimeout(15_000);
        conn.setReadTimeout(120_000);
        int code = conn.getResponseCode();
        if (code != 200) {
            throw new IOException("download failed, HTTP " + code + " for " + url);
        }
        try (InputStream in = conn.getInputStream(); OutputStream out = new FileOutputStream(dest)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        }
    }

    private static String sha256(File file) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
        try (InputStream in = new FileInputStream(file)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) != -1) digest.update(buf, 0, n);
        }
        byte[] hash = digest.digest();
        StringBuilder sb = new StringBuilder(hash.length * 2);
        for (byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** Shells out to the system {@code tar} - deliberately not a hand-rolled parser for a security-relevant archive. */
    private static void extractTarGz(File archive, File destDir) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("tar", "-xzf", archive.getAbsolutePath(), "-C", destDir.getAbsolutePath());
        pb.redirectErrorStream(true);
        Process p;
        try {
            p = pb.start();
        } catch (IOException e) {
            throw new IOException("could not run 'tar' to extract the Tor binary archive - is 'tar' on PATH? "
                    + "(standard on Linux/macOS; Windows 10 1803+/Server 2019+ ship it too): " + e.getMessage(), e);
        }
        String output = readAll(p.getInputStream());
        int exit;
        try {
            exit = p.waitFor();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while extracting Tor binary archive", e);
        }
        if (exit != 0) {
            throw new IOException("tar extraction failed (exit " + exit + "): " + output);
        }
    }

    private static String readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        byte[] chunk = new byte[4096];
        int n;
        while ((n = in.read(chunk)) != -1) buf.write(chunk, 0, n);
        return buf.toString("UTF-8");
    }

    /** Owner-only permissions on POSIX (Linux/macOS); a no-op on Windows, where the per-user profile directory is already private. */
    static void restrictToOwner(File dir) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
            Files.setPosixFilePermissions(dir.toPath(), perms);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Non-POSIX filesystem (Windows) - nothing to do.
        }
    }

    private static void deleteRecursive(File f) {
        if (f == null || !f.exists()) return;
        File[] children = f.listFiles();
        if (children != null) for (File c : children) deleteRecursive(c);
        f.delete();
    }
}