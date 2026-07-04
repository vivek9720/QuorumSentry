package io.quorumsentry.util;

public final class IpAddress {
    private IpAddress() {}

    public static long parseV4(String text) {
        if (text == null) {
            throw new IllegalArgumentException("ip is null");
        }
        String[] parts = text.trim().split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("expected IPv4 address: " + text);
        }
        long out = 0;
        for (String part : parts) {
            int value = Integer.parseInt(part);
            if (value < 0 || value > 255) {
                throw new IllegalArgumentException("IPv4 octet out of range: " + text);
            }
            out = (out << 8) | value;
        }
        return out;
    }

    public static boolean inCidr(String address, String cidr) {
        String[] parts = cidr.split("/");
        long ip = parseV4(address);
        long net = parseV4(parts[0]);
        int prefix = parts.length == 1 ? 32 : Integer.parseInt(parts[1]);
        long mask = prefix == 0 ? 0 : 0xffffffffL << (32 - prefix);
        return (ip & mask) == (net & mask);
    }

    public static boolean isPrivate(String address) {
        return inCidr(address, "10.0.0.0/8")
                || inCidr(address, "172.16.0.0/12")
                || inCidr(address, "192.168.0.0/16");
    }
}
