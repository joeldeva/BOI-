// DeceptiScope Defensive WebView Observer
// Observes WebView bridge interfaces and URL loading hooks safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        try {
            var WebView = Java.use("android.webkit.WebView");

            // 1. Hook addJavascriptInterface
            try {
                var originalAddJs = WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String");
                originalAddJs.implementation = function(object, name) {
                    try {
                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "webview",
                            event_type: "WEBVIEW_INTERFACE_ADDED",
                            timestamp_ms: Date.now(),
                            api: "android.webkit.WebView.addJavascriptInterface",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                interface_name: name ? name.toString() : "",
                                object_class: object ? object.getClass().getName() : ""
                            }
                        });
                    } catch(e) {}
                    return originalAddJs.call(this, object, name);
                };
            } catch(err1) {}

            // 2. Hook loadUrl(String)
            try {
                var originalLoadUrl = WebView.loadUrl.overload("java.lang.String");
                originalLoadUrl.implementation = function(url) {
                    try {
                        var strUrl = url ? url.toString() : "";
                        var hasSyntheticMarker = (strUrl.indexOf("DS-TEST-") !== -1 || strUrl.indexOf("BOI-TEST-") !== -1);
                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "webview",
                            event_type: "WEBVIEW_URL_LOADED",
                            timestamp_ms: Date.now(),
                            api: "android.webkit.WebView.loadUrl(String)",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                url: strUrl,
                                has_synthetic_marker: hasSyntheticMarker
                            }
                        });
                    } catch(e) {}
                    return originalLoadUrl.call(this, url);
                };
            } catch(err2) {}
        } catch(err) {}
    });
})();
