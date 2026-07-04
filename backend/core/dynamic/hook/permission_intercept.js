/**
 * Garudatva v3 — Permission Request Hook
 * Detects the app requesting dangerous runtime permissions during dynamic
 * analysis. Hooks both the framework entry point and the AndroidX/support
 * wrapper apps commonly call directly.
 * Output: send({type: 'permission_event', data: {...}})
 */

'use strict';

function logPermission(entry) {
    entry.timestamp = new Date().toISOString();
    send({ type: 'permission_event', data: entry });
}

Java.perform(function () {

    // ── Activity.requestPermissions (framework, API 23+) ─────────────
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.requestPermissions.overload('[Ljava.lang.String;', 'int').implementation = function (permissions, requestCode) {
            try {
                var perms = [];
                for (var i = 0; i < permissions.length; i++) {
                    perms.push(permissions[i]);
                }
                logPermission({
                    type: 'PERMISSION_REQUEST',
                    permissions: perms,
                    request_code: requestCode,
                    source: 'Activity.requestPermissions',
                });
            } catch (e) {}
            return this.requestPermissions(permissions, requestCode);
        };
    } catch (e) {
        console.log('[garudatva] Activity.requestPermissions hook failed: ' + e.message);
    }

    // ── ActivityCompat.requestPermissions (AndroidX wrapper) ──────────
    try {
        var ActivityCompat = Java.use('androidx.core.app.ActivityCompat');
        ActivityCompat.requestPermissions.overload(
            'android.app.Activity', '[Ljava.lang.String;', 'int'
        ).implementation = function (activity, permissions, requestCode) {
            try {
                var perms = [];
                for (var i = 0; i < permissions.length; i++) {
                    perms.push(permissions[i]);
                }
                logPermission({
                    type: 'PERMISSION_REQUEST',
                    permissions: perms,
                    request_code: requestCode,
                    source: 'ActivityCompat.requestPermissions',
                });
            } catch (e) {}
            return this.requestPermissions(activity, permissions, requestCode);
        };
    } catch (e) {
        // Not present if the app doesn't use androidx.core — not an error
    }

    console.log('[garudatva] permission_intercept.js loaded');
});
