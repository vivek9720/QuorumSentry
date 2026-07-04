import io.quorumsentry.QuorumSentry;

public class FlowFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            QuorumSentry.parseFlows(data);
        } catch (io.quorumsentry.core.ParseException | IllegalArgumentException ignored) {
        }
    }
}
