import io.quorumsentry.QuorumSentry;

public class ThreatBundleFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            QuorumSentry.parseBundle(data);
        } catch (io.quorumsentry.core.ParseException | IllegalArgumentException ignored) {
        }
    }
}
