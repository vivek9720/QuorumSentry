package io.quorumsentry.enrich;

import java.nio.charset.StandardCharsets;

public final class EntropyMeter {
    public double shannon(String text) {
        byte[] bytes = text == null ? new byte[0] : text.getBytes(StandardCharsets.UTF_8);
        if (bytes.length == 0) {
            return 0.0;
        }
        int[] counts = new int[256];
        for (byte b : bytes) counts[b & 0xff]++;
        double entropy = 0.0;
        for (int count : counts) {
            if (count == 0) continue;
            double p = (double) count / (double) bytes.length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    public boolean suspiciousToken(String token) {
        return token != null && token.length() > 18 && shannon(token) > 4.0;
    }
}
