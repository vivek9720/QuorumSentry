import io.quorumsentry.QuorumSentry;

public class ArchiveFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            QuorumSentry.evaluateArchive(data);
        } catch (io.quorumsentry.core.ParseException | IllegalArgumentException ignored) {
        }
    }
}
