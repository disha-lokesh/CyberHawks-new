/**
 * Garudatva v3 — Clipboard Monitoring Hook (Forensic Stub)
 * Detects clipboard hijacking — malware replacing copied UPI IDs
 * with attacker's VPA. Logs SET operations from the analyzed app only.
 * Output: /data/local/tmp/garudatva_clipboard.json
 */

'use strict';

var clipboardLog = [];

function logClipboard(entry) {
    entry.timestamp = new Date().toISOString();
    clipboardLog.push(entry);
    send({ type: 'clipboard_event', data: entry });
}

Java.perform(function () {

    // ── ClipboardManager.setPrimaryClip — detect clipboard writes ────
    // Malware replacing victim's copied UPI ID with attacker's VPA
    // is the #1 UPI fraud technique. Logged when the analyzed app
    // calls setPrimaryClip during dynamic analysis session.
    try {
        var ClipboardManager = Java.use('android.content.ClipboardManager');

        ClipboardManager.setPrimaryClip.implementation = function (clip) {
            try {
                var itemCount = clip ? clip.getItemCount() : 0;
                logClipboard({
                    type: 'CLIPBOARD_SET',
                    item_count: itemCount,
                    // Content not captured — presence of SET during analysis
                    // is the forensic signal (malware should not write clipboard)
                });
            } catch (e) {}
            return this.setPrimaryClip(clip);
        };
    } catch (e) {
        console.log('[garudatva] ClipboardManager hook failed: ' + e.message);
    }

    console.log('[garudatva] clipboard_intercept.js loaded');
});
