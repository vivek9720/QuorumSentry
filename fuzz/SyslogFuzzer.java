import io.quorumsentry.QuorumSentry;

public class SyslogFuzzer {
    public static void fuzzerTestOneInput(byte[] data) {
        try {
            QuorumSentry.parseSyslog(data);
        } catch (io.quorumsentry.core.ParseException | IllegalArgumentException ignored) {
        }
    }
}
