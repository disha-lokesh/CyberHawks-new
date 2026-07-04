/**
 * Garudatva v3 — Crypto Key Extraction Hook (Forensic Logger)
 * Hooks javax.crypto classes to log cipher usage metadata.
 * Uses hashCode() to tie each Cipher object to its exact payload — critical
 * when multiple encryptions run simultaneously in banking trojans.
 * Logs: algorithm, mode, IV presence, cipher ID — NOT raw key bytes.
 * Output: /data/local/tmp/garudatva_crypto.json
 */

'use strict';

var cryptoLog = [];

function logCrypto(entry) {
    entry.timestamp = new Date().toISOString();
    cryptoLog.push(entry);
    send({ type: 'crypto_event', data: entry });
}

Java.perform(function () {

    // ── SecretKeySpec — log algorithm and key length ──────────────────
    try {
        var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
        SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (keyBytes, algorithm) {
            logCrypto({
                type: 'SECRET_KEY_SPEC',
                algorithm: algorithm,
                key_length_bits: keyBytes.length * 8,
                // key_bytes NOT logged — forensic report uses algorithm + length
            });
            return this.$init(keyBytes, algorithm);
        };
    } catch (e) {
        console.log('[garudatva] SecretKeySpec hook failed: ' + e.message);
    }

    // ── IvParameterSpec — log IV length ──────────────────────────────
    try {
        var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
        IvParameterSpec.$init.overload('[B').implementation = function (iv) {
            logCrypto({
                type: 'IV_PARAMETER_SPEC',
                iv_length_bytes: iv.length,
                // iv bytes NOT logged
            });
            return this.$init(iv);
        };
    } catch (e) {}

    // ── Cipher.getInstance — log algorithm string ─────────────────────
    try {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
            logCrypto({
                type: 'CIPHER_GET_INSTANCE',
                transformation: transformation,
            });
            return this.getInstance(transformation);
        };
    } catch (e) {}

    // ── Cipher.init — log cipher ID (hashCode) + mode ────────────────
    // hashCode() on the Cipher object ties this init to its doFinal call.
    // When multiple encryptions run simultaneously, this is what links
    // each key to its exact encrypted payload in the forensic report.
    try {
        var Cipher2 = Java.use('javax.crypto.Cipher');
        Cipher2.init.overload('int', 'java.security.Key').implementation = function (opmode, key) {
            logCrypto({
                type: 'CIPHER_INIT',
                cipher_id: this.hashCode(),   // unique per Cipher object instance
                opmode: opmode,               // 1=ENCRYPT_MODE, 2=DECRYPT_MODE
                algorithm: this.getAlgorithm(),
            });
            return this.init(opmode, key);
        };

        Cipher2.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, params) {
            logCrypto({
                type: 'CIPHER_INIT_WITH_PARAMS',
                cipher_id: this.hashCode(),
                opmode: opmode,
                algorithm: this.getAlgorithm(),
                has_iv: params !== null,
            });
            return this.init(opmode, key, params);
        };
    } catch (e) {}

    // ── Cipher.doFinal — log cipher ID + output size ──────────────────
    // Links back to the Cipher.init entry via cipher_id (hashCode).
    // Output size tells investigators payload length without exposing content.
    try {
        var Cipher3 = Java.use('javax.crypto.Cipher');
        Cipher3.doFinal.overload('[B').implementation = function (input) {
            var result = this.doFinal(input);
            logCrypto({
                type: 'CIPHER_DO_FINAL',
                cipher_id: this.hashCode(),
                input_length_bytes: input ? input.length : 0,
                output_length_bytes: result ? result.length : 0,
                // plaintext NOT captured — use input_length for report
            });
            return result;
        };
    } catch (e) {}

    // ── Base64 encode — signals exfil encoding ────────────────────────
    try {
        var Base64 = Java.use('android.util.Base64');
        Base64.encodeToString.overload('[B', 'int').implementation = function (input, flags) {
            var result = this.encodeToString(input, flags);
            logCrypto({
                type: 'BASE64_ENCODE',
                input_length: input ? input.length : 0,
                output_length: result ? result.length() : 0,
            });
            return result;
        };
    } catch (e) {}

    console.log('[garudatva] crypto_key_extract.js loaded');
});
