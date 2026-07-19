package com.fraudsdk.transport;

import android.content.Context;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Persistent store-and-forward queue: newline-delimited JSON on disk.
 * Networks drop constantly in the field; nothing is lost across restarts.
 * Bounded at MAX_BYTES with oldest-first eviction.
 */
public final class EventQueue {

    private static final long MAX_BYTES = 512 * 1024;   // ~512KB cap on device
    private final File file;
    private final Object lock = new Object();

    public EventQueue(Context app) {
        this.file = new File(app.getFilesDir(), "fraudsdk_queue.ndjson");
    }

    public void offer(JSONObject event) {
        synchronized (lock) {
            try {
                if (file.length() > MAX_BYTES) evictOldest();
                try (FileOutputStream fos = new FileOutputStream(file, true)) {
                    fos.write(event.toString().getBytes(StandardCharsets.UTF_8));
                    fos.write('\n');
                }
            } catch (Exception ignored) {}
        }
    }

    /** Drain up to max events. Caller must ack() with the count actually uploaded. */
    public List<String> peek(int max) {
        synchronized (lock) {
            List<String> out = new ArrayList<>();
            if (!file.exists()) return out;
            try (BufferedReader r = new BufferedReader(new FileReader(file))) {
                String line;
                while (out.size() < max && (line = r.readLine()) != null) {
                    if (!line.isEmpty()) out.add(line);
                }
            } catch (Exception ignored) {}
            return out;
        }
    }

    /** Remove the first n lines after a successful upload. */
    public void ack(int n) {
        synchronized (lock) {
            try {
                List<String> all = new ArrayList<>();
                try (BufferedReader r = new BufferedReader(new FileReader(file))) {
                    String line;
                    while ((line = r.readLine()) != null) all.add(line);
                }
                try (FileOutputStream fos = new FileOutputStream(file, false)) {
                    for (int i = n; i < all.size(); i++) {
                        fos.write(all.get(i).getBytes(StandardCharsets.UTF_8));
                        fos.write('\n');
                    }
                }
            } catch (Exception ignored) {}
        }
    }

    private void evictOldest() {
        ack(25);   // drop 25 oldest events when over cap
    }
}
