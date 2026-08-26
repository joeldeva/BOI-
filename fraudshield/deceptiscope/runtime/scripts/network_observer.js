// DeceptiScope Defensive Network Observer
// Observes HTTP transmission pre-encryption and raw sockets safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        // 1. OkHttp3 client hook
        try {
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Request = Java.use("okhttp3.Request");

            OkHttpClient.newCall.implementation = function(request) {
                try {
                    var url = request ? request.url().toString() : "";
                    var method = request ? request.method().toString() : "GET";
                    var hasSyntheticMarker = (url.indexOf("BOI-TEST-") !== -1);

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
                            has_synthetic_marker: hasSyntheticMarker
                        }
                    });
                } catch(e) {}
                return this.newCall(request);
            };
        } catch(err) {}

        // 2. HttpURLConnection hook
        try {
            var URL = Java.use("java.net.URL");
            URL.openConnection.overload().implementation = function() {
                try {
                    var url = this.toString();
                    var hasSyntheticMarker = (url.indexOf("BOI-TEST-") !== -1);

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
                return this.openConnection();
            };
        } catch(err) {}

        // 3. Socket connect hook
        try {
            var Socket = Java.use("java.net.Socket");
            Socket.connect.overload("java.net.SocketAddress", "int").implementation = function(endpoint, timeout) {
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
                return this.connect(endpoint, timeout);
            };
        } catch(err) {}
    });
})();
