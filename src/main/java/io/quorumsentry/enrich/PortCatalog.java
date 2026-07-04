package io.quorumsentry.enrich;

import java.util.HashMap;
import java.util.Map;

public final class PortCatalog {
    private final Map<Integer, String> names = new HashMap<>();

    public PortCatalog() {
        names.put(22, "ssh");
        names.put(25, "smtp");
        names.put(53, "dns");
        names.put(80, "http");
        names.put(110, "pop3");
        names.put(143, "imap");
        names.put(389, "ldap");
        names.put(443, "https");
        names.put(445, "smb");
        names.put(3389, "rdp");
        names.put(5432, "postgres");
        names.put(6379, "redis");
        names.put(9200, "elasticsearch");
    }

    public String service(int port) {
        return names.getOrDefault(port, "port-" + port);
    }

    public boolean administrative(int port) {
        return port == 22 || port == 3389 || port == 5985 || port == 5986;
    }

    public boolean dataStore(int port) {
        return port == 5432 || port == 3306 || port == 6379 || port == 9200;
    }
}
