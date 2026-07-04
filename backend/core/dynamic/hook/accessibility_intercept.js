/**
 * Garudatva v3 — Accessibility Abuse Detection Hook
 * Detects whether the analyzed app registers an AccessibilityService
 * and what event types it listens for — the forensic signal is
 * WHICH event types are requested, not the content of those events.
 * Accessibility abuse is #1 technique in Indian banking trojans.
 * Output: /data/local/tmp/garudatva_accessibility.json
 */

'use strict';

var accessibilityLog = [];

function logAccessibility(entry) {
    entry.timestamp = new Date().toISOString();
    accessibilityLog.push(entry);
    send({ type: 'accessibility_event', data: entry });
}

Java.perform(function () {

    // ── AccessibilityService.onAccessibilityEvent ─────────────────────
    // Log WHICH event types the app receives — not the content.
    // TYPE_VIEW_TEXT_CHANGED on banking apps = keylogging signal.
    // TYPE_WINDOW_STATE_CHANGED = app switching monitor.
    // performAction CLICK on other apps = clickjacking.
    try {
        var AccessibilityService = Java.use('android.accessibilityservice.AccessibilityService');

        AccessibilityService.onAccessibilityEvent.implementation = function (event) {
            try {
                var eventType = event ? event.getEventType() : -1;
                var packageName = event ? event.getPackageName() : null;

                // Map event type int to name for report readability
                var EVENT_TYPES = {
                    1:    'TYPE_VIEW_CLICKED',
                    2:    'TYPE_VIEW_LONG_CLICKED',
                    8:    'TYPE_VIEW_TEXT_CHANGED',       // keylogging signal
                    32:   'TYPE_WINDOW_STATE_CHANGED',    // app switching monitor
                    2048: 'TYPE_VIEW_SCROLLED',
                    4096: 'TYPE_VIEW_TEXT_SELECTION_CHANGED',
                    32768:'TYPE_WINDOWS_CHANGED',
                };

                logAccessibility({
                    type: 'ACCESSIBILITY_EVENT',
                    event_type_id: eventType,
                    event_type_name: EVENT_TYPES[eventType] || 'TYPE_UNKNOWN_' + eventType,
                    source_package: packageName ? packageName.toString() : null,
                    // Event content NOT captured — event type is the forensic signal
                });
            } catch (e) {}

            return this.onAccessibilityEvent(event);
        };
    } catch (e) {
        console.log('[garudatva] AccessibilityService hook: ' + e.message);
    }

    // ── AccessibilityNodeInfo.performAction ───────────────────────────
    // Detect automated clicking on other app windows = clickjacking
    try {
        var AccessibilityNodeInfo = Java.use('android.view.accessibility.AccessibilityNodeInfo');

        AccessibilityNodeInfo.performAction.overload('int').implementation = function (action) {
            var result = this.performAction(action);
            var ACTION_CLICK = 16;
            var ACTION_SET_TEXT = 2097152;

            if (action === ACTION_CLICK || action === ACTION_SET_TEXT) {
                logAccessibility({
                    type: 'ACCESSIBILITY_PERFORM_ACTION',
                    action_id: action,
                    action_name: action === ACTION_CLICK ? 'ACTION_CLICK' : 'ACTION_SET_TEXT',
                    // Automated actions on other apps = clickjacking/form-fill signal
                });
            }
            return result;
        };
    } catch (e) {}

    console.log('[garudatva] accessibility_intercept.js loaded');
});
