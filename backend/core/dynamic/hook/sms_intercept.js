/**
 * Garudatva v3 — SMS Intercept Hook
 * Hooks SmsManager send/receive and ContentResolver SMS queries.
 * Captures OTP theft and SMS forwarding attempts.
 * Output: /data/local/tmp/garudatva_sms.json
 */

'use strict';

var smsLog = [];

function logSMS(entry) {
    entry.timestamp = new Date().toISOString();
    smsLog.push(entry);
    send({ type: 'sms_event', data: entry });
}

Java.perform(function () {

    // ── SmsManager.sendTextMessage ────────────────────────────────────
    try {
        var SmsManager = Java.use('android.telephony.SmsManager');

        SmsManager.sendTextMessage.implementation = function (
            destinationAddress, scAddress, text, sentIntent, deliveryIntent
        ) {
            logSMS({
                type: 'SMS_SEND',
                destination: destinationAddress,
                sc_address: scAddress,
                message_length: text ? text.length() : 0,
                message_preview: text ? text.toString().substring(0, 100) : null,
            });
            return this.sendTextMessage(destinationAddress, scAddress, text, sentIntent, deliveryIntent);
        };
    } catch (e) {
        console.log('[garudatva] SmsManager.sendTextMessage hook failed: ' + e.message);
    }

    // ── SmsManager.sendMultipartTextMessage ───────────────────────────
    try {
        var SmsManager2 = Java.use('android.telephony.SmsManager');
        SmsManager2.sendMultipartTextMessage.implementation = function (
            destinationAddress, scAddress, parts, sentIntents, deliveryIntents
        ) {
            logSMS({
                type: 'SMS_SEND_MULTIPART',
                destination: destinationAddress,
                parts_count: parts ? parts.size() : 0,
            });
            return this.sendMultipartTextMessage(destinationAddress, scAddress, parts, sentIntents, deliveryIntents);
        };
    } catch (e) {}

    // ── ContentResolver query on SMS URI ─────────────────────────────
    try {
        var ContentResolver = Java.use('android.content.ContentResolver');
        ContentResolver.query.overload(
            'android.net.Uri',
            '[Ljava.lang.String;',
            'java.lang.String',
            '[Ljava.lang.String;',
            'java.lang.String'
        ).implementation = function (uri, projection, selection, selectionArgs, sortOrder) {
            var uriStr = uri ? uri.toString() : '';
            if (uriStr.indexOf('sms') !== -1 || uriStr.indexOf('mms') !== -1) {
                logSMS({
                    type: 'SMS_CONTENT_QUERY',
                    uri: uriStr,
                    selection: selection,
                });
            }
            return this.query(uri, projection, selection, selectionArgs, sortOrder);
        };
    } catch (e) {}

    // ── BroadcastReceiver for incoming SMS ────────────────────────────
    try {
        var SmsMessage = Java.use('android.telephony.SmsMessage');
        SmsMessage.createFromPdu.overload('[B').implementation = function (pdu) {
            var msg = this.createFromPdu(pdu);
            if (msg) {
                logSMS({
                    type: 'SMS_RECEIVE',
                    originating_address: msg.getOriginatingAddress(),
                    message_length: msg.getMessageBody() ? msg.getMessageBody().length() : 0,
                    message_preview: msg.getMessageBody() ?
                        msg.getMessageBody().toString().substring(0, 100) : null,
                });
            }
            return msg;
        };
    } catch (e) {}

    console.log('[garudatva] sms_intercept.js loaded');
});
