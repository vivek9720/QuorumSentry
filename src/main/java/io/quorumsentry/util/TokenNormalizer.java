package io.quorumsentry.util;

import java.text.Normalizer;
import java.util.Locale;

public final class TokenNormalizer {
    private TokenNormalizer() {}

    public static String token(String input) {
        if (input == null) {
            return "";
        }
        String normalized = Normalizer.normalize(input, Normalizer.Form.NFKC).toLowerCase(Locale.ROOT).trim();
        StringBuilder out = new StringBuilder(normalized.length());
        boolean dash = false;
        for (int i = 0; i < normalized.length(); i++) {
            char c = normalized.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '.' || c == ':' || c == '_' || c == '/') {
                out.append(c);
                dash = false;
            } else if (!dash) {
                out.append('-');
                dash = true;
            }
        }
        while (out.length() > 0 && out.charAt(out.length() - 1) == '-') {
            out.setLength(out.length() - 1);
        }
        return out.toString();
    }

    public static int stableBucket(String input, int buckets) {
        if (buckets <= 0) {
            return 0;
        }
        int h = 1125899907;
        String t = token(input);
        for (int i = 0; i < t.length(); i++) {
            h = 31 * h + t.charAt(i);
        }
        return Math.floorMod(h, buckets);
    }
}
