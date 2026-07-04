import io.quorumsentry.QuorumSentry;

public class PolicyFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            QuorumSentry.parsePolicy(data);
        } catch (io.quorumsentry.core.ParseException | IllegalArgumentException ignored) {
        }
    }
}
