package com.fraudsdk.capture;

import android.app.Activity;
import android.app.Application;
import android.os.Bundle;
import android.view.MotionEvent;
import android.view.Window;

import com.fraudsdk.session.SessionManager;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Passive touch capture: wraps each Activity's Window.Callback to observe
 * MotionEvents without consuming them. Emits aggregated stroke summaries
 * (not raw streams) every FLUSH_MS to keep payloads small:
 * duration, path length, straightness, mean/max pressure, touch area,
 * inter-tap interval — the core behavioral-biometric features.
 */
public final class TouchCapture implements Application.ActivityLifecycleCallbacks {

    private static final long FLUSH_MS = 10_000;
    private static final int MAX_STROKES_PER_FLUSH = 40;

    private final SessionManager sessions;
    private final JSONArray strokes = new JSONArray();
    private long lastFlush = System.currentTimeMillis();
    private long lastTapUp = 0;

    // current stroke accumulators
    private long downTs;
    private float downX, downY, pathLen, lastX, lastY, maxPressure, sumPressure, maxSize;
    private int samples;

    public TouchCapture(SessionManager sessions) { this.sessions = sessions; }

    @Override
    public void onActivityResumed(Activity activity) {
        Window w = activity.getWindow();
        Window.Callback original = w.getCallback();
        if (original instanceof Wrapped) return;   // already wrapped
        w.setCallback(new Wrapped(original));
    }

    /** Delegating callback: observes touch, never alters dispatch. */
    private final class Wrapped extends WindowCallbackDelegate {
        Wrapped(Window.Callback delegate) { super(delegate); }

        @Override
        public boolean dispatchTouchEvent(MotionEvent ev) {
            try { observe(ev); } catch (Throwable ignored) {}
            return super.dispatchTouchEvent(ev);
        }
    }

    private void observe(MotionEvent ev) {
        sessions.touch();   // any interaction resets idle timer
        switch (ev.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                downTs = ev.getEventTime();
                downX = lastX = ev.getX();
                downY = lastY = ev.getY();
                pathLen = 0; maxPressure = 0; sumPressure = 0; maxSize = 0; samples = 0;
                accumulate(ev);
                break;
            case MotionEvent.ACTION_MOVE:
                for (int h = 0; h < ev.getHistorySize(); h++) {
                    step(ev.getHistoricalX(h), ev.getHistoricalY(h));
                }
                step(ev.getX(), ev.getY());
                accumulate(ev);
                break;
            case MotionEvent.ACTION_UP:
                accumulate(ev);
                finishStroke(ev);
                break;
            default:
                break;
        }
    }

    private void step(float x, float y) {
        pathLen += Math.hypot(x - lastX, y - lastY);
        lastX = x; lastY = y;
    }

    private void accumulate(MotionEvent ev) {
        float p = ev.getPressure(), s = ev.getSize();
        maxPressure = Math.max(maxPressure, p);
        sumPressure += p;
        maxSize = Math.max(maxSize, s);
        samples++;
    }

    private void finishStroke(MotionEvent ev) {
        try {
            long upTs = ev.getEventTime();
            float dx = ev.getX() - downX, dy = ev.getY() - downY;
            float direct = (float) Math.hypot(dx, dy);
            JSONObject s = new JSONObject();
            s.put("t", downTs);
            s.put("dur", upTs - downTs);
            s.put("len", Math.round(pathLen));
            // straightness 1.0 = perfect line; near 0 for scribbles. Bots are unnaturally straight.
            s.put("straight", pathLen > 0 ? Math.round(100f * direct / pathLen) / 100f : 1.0);
            s.put("pMax", Math.round(maxPressure * 100f) / 100f);
            s.put("pAvg", samples > 0 ? Math.round(sumPressure / samples * 100f) / 100f : 0);
            s.put("area", Math.round(maxSize * 100f) / 100f);
            s.put("gap", lastTapUp > 0 ? downTs - lastTapUp : -1);   // inter-tap interval
            lastTapUp = upTs;

            synchronized (strokes) {
                if (strokes.length() < MAX_STROKES_PER_FLUSH) strokes.put(s);
            }
            maybeFlush();
        } catch (Exception ignored) {}
    }

    private void maybeFlush() {
        long now = System.currentTimeMillis();
        if (now - lastFlush < FLUSH_MS) return;
        JSONArray out;
        synchronized (strokes) {
            if (strokes.length() == 0) return;
            out = new JSONArray();
            for (int i = 0; i < strokes.length(); i++) out.put(strokes.opt(i));
            while (strokes.length() > 0) strokes.remove(0);
        }
        lastFlush = now;
        final JSONArray batch = out;
        sessions.executor().execute(() -> {
            try {
                sessions.enqueuePassive("TOUCH_STROKES",
                        new JSONObject().put("strokes", batch));
            } catch (Exception ignored) {}
        });
    }

    // ---- unused lifecycle hooks ----
    @Override public void onActivityCreated(Activity a, Bundle b) {}
    @Override public void onActivityStarted(Activity a) {}
    @Override public void onActivityPaused(Activity a) {}
    @Override public void onActivityStopped(Activity a) {}
    @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
    @Override public void onActivityDestroyed(Activity a) {}
}
