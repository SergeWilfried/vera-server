package com.fraudsdk.capture;

import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.SearchEvent;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityEvent;

/** Pure pass-through Window.Callback. Subclass and override what you observe. */
class WindowCallbackDelegate implements Window.Callback {
    private final Window.Callback d;
    WindowCallbackDelegate(Window.Callback d) { this.d = d; }

    @Override public boolean dispatchKeyEvent(KeyEvent e) { return d.dispatchKeyEvent(e); }
    @Override public boolean dispatchKeyShortcutEvent(KeyEvent e) { return d.dispatchKeyShortcutEvent(e); }
    @Override public boolean dispatchTouchEvent(MotionEvent e) { return d.dispatchTouchEvent(e); }
    @Override public boolean dispatchTrackballEvent(MotionEvent e) { return d.dispatchTrackballEvent(e); }
    @Override public boolean dispatchGenericMotionEvent(MotionEvent e) { return d.dispatchGenericMotionEvent(e); }
    @Override public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent e) { return d.dispatchPopulateAccessibilityEvent(e); }
    @Override public View onCreatePanelView(int i) { return d.onCreatePanelView(i); }
    @Override public boolean onCreatePanelMenu(int i, Menu m) { return d.onCreatePanelMenu(i, m); }
    @Override public boolean onPreparePanel(int i, View v, Menu m) { return d.onPreparePanel(i, v, m); }
    @Override public boolean onMenuOpened(int i, Menu m) { return d.onMenuOpened(i, m); }
    @Override public boolean onMenuItemSelected(int i, MenuItem mi) { return d.onMenuItemSelected(i, mi); }
    @Override public void onWindowAttributesChanged(WindowManager.LayoutParams lp) { d.onWindowAttributesChanged(lp); }
    @Override public void onContentChanged() { d.onContentChanged(); }
    @Override public void onWindowFocusChanged(boolean b) { d.onWindowFocusChanged(b); }
    @Override public void onAttachedToWindow() { d.onAttachedToWindow(); }
    @Override public void onDetachedFromWindow() { d.onDetachedFromWindow(); }
    @Override public void onPanelClosed(int i, Menu m) { d.onPanelClosed(i, m); }
    @Override public boolean onSearchRequested() { return d.onSearchRequested(); }
    @Override public boolean onSearchRequested(SearchEvent e) { return d.onSearchRequested(e); }
    @Override public ActionMode onWindowStartingActionMode(ActionMode.Callback c) { return d.onWindowStartingActionMode(c); }
    @Override public ActionMode onWindowStartingActionMode(ActionMode.Callback c, int t) { return d.onWindowStartingActionMode(c, t); }
    @Override public void onActionModeStarted(ActionMode m) { d.onActionModeStarted(m); }
    @Override public void onActionModeFinished(ActionMode m) { d.onActionModeFinished(m); }
}
