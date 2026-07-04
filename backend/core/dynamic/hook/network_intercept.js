/**
 * Garudatva v3 — Network Hooks
 * Intercepts all major Android network API classes.
 * Logs every URL before encryption occurs.
 * Output written to /data/local/tmp/garudatva_network.json
 */

'use strict';

var networkLog = [];

function saveLog() {
    var fs = require('fs');
    try {
        var path = '/data/local/tmp/garudatva_network.json';
        var json = JSON.stringify(networkLog, null, 2);
        // Write via file descriptor
        send({ type: 'network_save', count: networkLog.length });
    } catch (e) {}
}

function logNetwork(entry) {
    entry.timestamp = new Date().toISOString();
    networkLog.push(entry);
    send({ type: 'network_event', data: entry });
}

Java.perform(function () {

    // ── OkHttp3 ──────────────────────────────────────────────────────
    try {
        var OkHttpClient = Java.use('okhttp3.OkHttpClient');
        var Request = Java.use('okhttp3.Request');
        var RealCall = Java.use('okhttp3.internal.connection.RealCall');

        RealCall.execute.implementation = function () {
            try {
                var request = this.request.value;
                logNetwork({
                    library: 'okhttp3',
                    method: request.method(),
                    url: request.url().toString(),
                    host: request.url().host(),
                    interceptor_class: null
                });
            } catch (e) {}
            return this.execute();
        };
    } catch (e) {
        console.log('[garudatva] OkHttp3 RealCall hook failed: ' + e.message);
    }

    // ── OkHttp3 newCall ───────────────────────────────────────────────
    try {
        var OkHttpClient2 = Java.use('okhttp3.OkHttpClient');
        OkHttpClient2.newCall.implementation = function (request) {
            try {
                logNetwork({
                    library: 'okhttp3.newCall',
                    method: request.method(),
                    url: request.url().toString(),
                    host: request.url().host()
                });
            } catch (e) {}
            return this.newCall(request);
        };
    } catch (e) {}

    // ── HttpURLConnection ─────────────────────────────────────────────
    try {
        var HttpURLConnection = Java.use('java.net.HttpURLConnection');
        HttpURLConnection.getInputStream.implementation = function () {
            try {
                logNetwork({
                    library: 'HttpURLConnection',
                    method: this.getRequestMethod(),
                    url: this.getURL().toString(),
                    host: this.getURL().getHost()
                });
            } catch (e) {}
            return this.getInputStream();
        };
    } catch (e) {}

    // ── HttpsURLConnection ────────────────────────────────────────────
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.getInputStream.implementation = function () {
            try {
                logNetwork({
                    library: 'HttpsURLConnection',
                    method: this.getRequestMethod(),
                    url: this.getURL().toString(),
                    host: this.getURL().getHost()
                });
            } catch (e) {}
            return this.getInputStream();
        };
    } catch (e) {}

    // ── InetAddress (DNS resolution) ──────────────────────────────────
    try {
        var InetAddress = Java.use('java.net.InetAddress');
        InetAddress.getByName.implementation = function (host) {
            if (host) {
                logNetwork({
                    library: 'InetAddress.getByName',
                    type: 'DNS_LOOKUP',
                    host: host,
                    url: host
                });
            }
            return this.getByName(host);
        };
    } catch (e) {}

    // ── Raw Socket connect ────────────────────────────────────────────
    try {
        var Socket = Java.use('java.net.Socket');
        Socket.connect.overload('java.net.SocketAddress', 'int').implementation = function (addr, timeout) {
            try {
                logNetwork({
                    library: 'java.net.Socket',
                    type: 'RAW_SOCKET',
                    url: addr.toString(),
                    host: addr.toString()
                });
            } catch (e) {}
            return this.connect(addr, timeout);
        };
    } catch (e) {}

    // ── Firebase Realtime Database ────────────────────────────────────
    try {
        var DatabaseReference = Java.use('com.google.firebase.database.DatabaseReference');
        DatabaseReference.setValue.overload('java.lang.Object').implementation = function (value) {
            try {
                logNetwork({
                    library: 'Firebase.DatabaseReference',
                    type: 'FIREBASE_WRITE',
                    url: this.toString(),
                    value_preview: value ? value.toString().substring(0, 200) : null
                });
            } catch (e) {}
            return this.setValue(value);
        };
    } catch (e) {}

    // ── Volley RequestQueue ───────────────────────────────────────────
    try {
        var Request2 = Java.use('com.android.volley.Request');
        Request2.getUrl.implementation = function () {
            var url = this.getUrl();
            try {
                logNetwork({
                    library: 'Volley',
                    method: this.getMethod(),
                    url: url
                });
            } catch (e) {}
            return url;
        };
    } catch (e) {}

    console.log('[garudatva] network_hooks.js loaded');
});
