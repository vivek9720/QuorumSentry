package io.quorumsentry.util;

import java.util.ArrayList;
import java.util.List;

public final class TextTable {
    private final List<String[]> rows = new ArrayList<>();

    public void add(String... columns) {
        rows.add(columns == null ? new String[0] : columns);
    }

    public String render() {
        int width = 0;
        for (String[] row : rows) {
            width = Math.max(width, row.length);
        }
        int[] widths = new int[width];
        for (String[] row : rows) {
            for (int i = 0; i < row.length; i++) {
                widths[i] = Math.max(widths[i], row[i] == null ? 0 : row[i].length());
            }
        }
        StringBuilder out = new StringBuilder();
        for (String[] row : rows) {
            for (int i = 0; i < row.length; i++) {
                String value = row[i] == null ? "" : row[i];
                out.append(value);
                for (int pad = value.length(); pad <= widths[i]; pad++) {
                    out.append(' ');
                }
            }
            out.append('\n');
        }
        return out.toString();
    }
}
