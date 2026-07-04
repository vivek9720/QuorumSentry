package io.quorumsentry.engine;

import io.quorumsentry.model.EventRecord;
import io.quorumsentry.model.FlowRecord;
import io.quorumsentry.model.ThreatIndicator;
import io.quorumsentry.util.TokenNormalizer;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class IncidentGraph {
    private final Map<String, Node> nodes = new HashMap<>();
    private final List<Edge> edges = new ArrayList<>();

    public Node node(String id, String kind) {
        return nodes.computeIfAbsent(TokenNormalizer.token(id), k -> new Node(k, kind));
    }

    public void ingest(EventRecord event) {
        Node host = node(event.host(), "host");
        Node category = node(event.category(), "category");
        connect(host, category, "emitted", event.severity().weight());
        for (Map.Entry<String, String> attr : event.attributes().entrySet()) {
            if (attr.getKey().contains("ip") || attr.getKey().contains("user") || attr.getKey().contains("hash")) {
                connect(host, node(attr.getValue(), attr.getKey()), attr.getKey(), event.severity().weight());
            }
        }
    }

    public void ingest(FlowRecord flow) {
        Node src = node(flow.sourceIp(), "ip");
        Node dst = node(flow.destinationIp(), "ip");
        int weight = flow.isLikelyScan() ? 6 : 1;
        connect(src, dst, flow.protocol() + ":" + flow.destinationPort(), weight);
    }

    public void ingest(ThreatIndicator indicator) {
        Node indicatorNode = node(indicator.id(), "indicator");
        Node valueNode = node(indicator.value(), indicator.type());
        connect(indicatorNode, valueNode, "observes", indicator.severity().weight());
        for (String label : indicator.labels()) {
            connect(indicatorNode, node(label, "label"), "labeled", 1);
        }
    }

    public void connect(Node from, Node to, String relation, int weight) {
        Edge edge = new Edge(from, to, relation, weight);
        from.out.add(edge);
        to.in.add(edge);
        edges.add(edge);
    }

    public List<Node> neighborhood(String id, int depth) {
        Node start = nodes.get(TokenNormalizer.token(id));
        List<Node> out = new ArrayList<>();
        if (start == null) {
            return out;
        }
        Set<Node> seen = new HashSet<>();
        ArrayDeque<NodeDepth> queue = new ArrayDeque<>();
        queue.add(new NodeDepth(start, 0));
        seen.add(start);
        while (!queue.isEmpty()) {
            NodeDepth current = queue.removeFirst();
            out.add(current.node);
            if (current.depth >= depth) {
                continue;
            }
            for (Edge e : current.node.out) {
                if (seen.add(e.to)) {
                    queue.add(new NodeDepth(e.to, current.depth + 1));
                }
            }
        }
        return out;
    }

    public int score(String id) {
        Node node = nodes.get(TokenNormalizer.token(id));
        if (node == null) {
            return 0;
        }
        int score = 0;
        for (Edge edge : node.in) {
            score += edge.weight;
        }
        for (Edge edge : node.out) {
            score += edge.weight / 2;
        }
        return score;
    }

    public int nodeCount() { return nodes.size(); }
    public int edgeCount() { return edges.size(); }

    private record NodeDepth(Node node, int depth) {}

    public static final class Node {
        private final String id;
        private final String kind;
        private final List<Edge> out = new ArrayList<>();
        private final List<Edge> in = new ArrayList<>();

        Node(String id, String kind) {
            this.id = id;
            this.kind = kind;
        }

        public String id() { return id; }
        public String kind() { return kind; }
    }

    public static final class Edge {
        private final Node from;
        private final Node to;
        private final String relation;
        private final int weight;

        Edge(Node from, Node to, String relation, int weight) {
            this.from = from;
            this.to = to;
            this.relation = relation;
            this.weight = weight;
        }

        public Node from() { return from; }
        public Node to() { return to; }
        public String relation() { return relation; }
        public int weight() { return weight; }
    }
}
