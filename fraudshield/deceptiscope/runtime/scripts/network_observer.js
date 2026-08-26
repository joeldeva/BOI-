// DeceptiScope Defensive Network Observer
// Observes HTTP transmission pre-encryption and raw sockets safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        // 1. OkHttp3 client hook with safe pre-TLS Request & RequestBody inspection
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var originalNewCall = OkHttpClient.newCall.overload("okhttp3.Request");

            originalNewCall.implementation = function(request) {
                try {
                    var url = request ? request.url().toString() : "";
                    var method = request ? request.method().toString() : "GET";
                    var bodyPreview = "";
                    var bodySize = 0;

                    if (request) {
                        try {
                            var requestBody = request.body();
                            if (requestBody) {
                                bodySize = requestBody.contentLength ? requestBody.contentLength() : 0;
                                try {
                                    var BufferCls = Java.use("okio.Buffer");
                                    var buffer = BufferCls.$new();
                                    requestBody.writeTo(buffer);
                                    var maxRead = Math.min(buffer.size(), 4096);
                                    bodyPreview = buffer.readUtf8(maxRead);
                                } catch(bErr) {
                                    bodyPreview = requestBody.toString();
                                }
                            }
                        } catch(rbErr) {}
                    }

                    var hasSyntheticMarker = (
                        url.indexOf("DS-TEST-") !== -1 ||
                        url.indexOf("BOI-TEST-") !== -1 ||
                        bodyPreview.indexOf("DS-TEST-") !== -1 ||
                        bodyPreview.indexOf("BOI-TEST-") !== -1
                    );

                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "network",
                        event_type: "HTTP_REQUEST_OBSERVED",
                        timestamp_ms: Date.now(),
                        api: "okhttp3.OkHttpClient.newCall",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            client: "OkHttp3",
                            method: method,
                            url: url,
                            body_size: bodySize,
                            body_preview_redacted: bodyPreview.length > 500 ? bodyPreview.substring(0, 500) + "..." : bodyPreview,
                            has_synthetic_marker: hasSyntheticMarker
                        }
                    });
                } catch(e) {}
                return originalNewCall.call(this, request);
            };
        } catch(err) {}

        // 2. HttpURLConnection hook
        try {
            var URL = Java.use("java.net.URL");
            var originalOpenConnection = URL.openConnection.overload();
            originalOpenConnection.implementation = function() {
                try {
                    var url = this.toString();
                    var hasSyntheticMarker = (url.indexOf("DS-TEST-") !== -1 || url.indexOf("BOI-TEST-") !== -1);

                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "network",
                        event_type: "URL_OPENED",
                        timestamp_ms: Date.now(),
                        api: "java.net.URL.openConnection",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            client: "HttpURLConnection",
                            url: url,
                            has_synthetic_marker: hasSyntheticMarker
                        }
                    });
                } catch(e) {}
                return originalOpenConnection.call(this);
            };
        } catch(err) {}

        // 3. Socket connect hook
        try {
            var Socket = Java.use("java.net.Socket");
            var originalSocketConnect = Socket.connect.overload("java.net.SocketAddress", "int");
            originalSocketConnect.implementation = function(endpoint, timeout) {
                try {
                    var addr = endpoint ? endpoint.toString() : "";
                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "network",
                        event_type: "SOCKET_CONNECT_OBSERVED",
                        timestamp_ms: Date.now(),
                        api: "java.net.Socket.connect",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            endpoint: addr,
                            timeout: timeout
                        }
                    });
                } catch(e) {}
                return originalSocketConnect.call(this, endpoint, timeout);
            };
        } catch(err) {}
    });
})();
