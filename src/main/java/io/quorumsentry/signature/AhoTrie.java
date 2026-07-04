package io.quorumsentry.signature;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class AhoTrie {
    private final Node root = new Node();

    public void add(String word, String id) {
        Node cur = root;
        for (int i = 0; i < word.length(); i++) {
            char c = Character.toLowerCase(word.charAt(i));
            cur = cur.next.computeIfAbsent(c, k -> new Node());
        }
        cur.outputs.add(id);
    }

    public void build() {
        ArrayDeque<Node> queue = new ArrayDeque<>();
        for (Node child : root.next.values()) {
            child.fail = root;
            queue.add(child);
        }
        while (!queue.isEmpty()) {
            Node cur = queue.removeFirst();
            for (Map.Entry<Character, Node> e : cur.next.entrySet()) {
                char c = e.getKey();
                Node target = e.getValue();
                Node fail = cur.fail;
                while (fail != null && !fail.next.containsKey(c)) {
                    fail = fail.fail;
                }
                target.fail = fail == null ? root : fail.next.get(c);
                target.outputs.addAll(target.fail.outputs);
                queue.add(target);
            }
        }
    }

    public List<String> find(String text) {
        List<String> out = new ArrayList<>();
        Node cur = root;
        for (int i = 0; i < text.length(); i++) {
            char c = Character.toLowerCase(text.charAt(i));
            while (cur != root && !cur.next.containsKey(c)) {
                cur = cur.fail;
            }
            cur = cur.next.getOrDefault(c, root);
            out.addAll(cur.outputs);
        }
        return out;
    }

    private static final class Node {
        private final Map<Character, Node> next = new HashMap<>();
        private final List<String> outputs = new ArrayList<>();
        private Node fail;
    }
}
