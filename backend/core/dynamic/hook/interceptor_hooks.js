/**
 * Garudatva v3 — OkHttp Interceptor Attribution Hook
 * Reads RealInterceptorChain.index to identify which interceptor
 * mutated each request — gives investigators the exact class name
 * e.g. "com.malware.EncryptBodyInterceptor"
 */

'use strict';

var interceptorLog = [];

function logInterceptor(entry) {
    entry.timestamp = new Date().toISOString();
    interceptorLog.push(entry);
    send({ type: 'interceptor_event', data: entry });
}

Java.perform(function () {

    try {
        var RealInterceptorChain = Java.use('okhttp3.internal.http.RealInterceptorChain');

        RealInterceptorChain.proceed.overload('okhttp3.Request').implementation = function (request) {
            try {
                var idx = this.index.value;
                var interceptors = this.interceptors.value;
                var className = 'unknown';

                if (idx > 0 && interceptors !== null && idx <= interceptors.size()) {
                    className = interceptors.get(idx - 1).getClass().getName();
                }

                // Only log non-OkHttp-internal interceptors (likely malware classes)
                var isInternal = className.startsWith('okhttp3.') ||
                                 className.startsWith('okio.') ||
                                 className === 'unknown';

                logInterceptor({
                    type: 'OKHTTP_INTERCEPTOR',
                    interceptor_class: className,
                    is_custom: !isInternal,
                    url: request.url().toString(),
                    method: request.method(),
                    chain_index: idx,
                });
            } catch (e) {}

            return this.proceed(request);
        };

        console.log('[garudatva] interceptor_hooks.js loaded');
    } catch (e) {
        console.log('[garudatva] interceptor_hooks.js failed: ' + e.message);
    }
});
