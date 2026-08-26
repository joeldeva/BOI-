// DeceptiScope Defensive Accessibility Observer
// Observes UI text harvesting and action injection hooks safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        try {
            var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

            // 1. Hook getText()
            try {
                var originalGetText = AccessibilityNodeInfo.getText.overload();
                originalGetText.implementation = function() {
                    var text = originalGetText.call(this);
                    try {
                        var strText = text ? text.toString() : "";
                        var viewId = (this.getViewIdResourceName() || "");
                        var pkg = (this.getPackageName() || "");
                        var hasSyntheticMarker = (strText.indexOf("DS-TEST-") !== -1 || strText.indexOf("BOI-TEST-") !== -1 || strText.indexOf("OTP") !== -1);

                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "accessibility",
                            event_type: "ACCESSIBILITY_TEXT_READ",
                            timestamp_ms: Date.now(),
                            api: "android.view.accessibility.AccessibilityNodeInfo.getText",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                target_ui_package: pkg ? pkg.toString() : "",
                                view_id: viewId ? viewId.toString() : "",
                                text_length: strText.length,
                                has_synthetic_marker: hasSyntheticMarker,
                                preview: strText.length > 50 ? strText.substring(0, 50) + "..." : strText
                            }
                        });
                    } catch(e) {}
                    return text;
                };
            } catch(err1) {}

            // 2. Hook performAction(int)
            try {
                var originalPerformAction = AccessibilityNodeInfo.performAction.overload("int");
                originalPerformAction.implementation = function(action) {
                    try {
                        var viewId = (this.getViewIdResourceName() || "");
                        var pkg = (this.getPackageName() || "");

                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "accessibility",
                            event_type: "ACCESSIBILITY_ACTION_PERFORMED",
                            timestamp_ms: Date.now(),
                            api: "android.view.accessibility.AccessibilityNodeInfo.performAction(int)",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                action_code: action,
                                target_ui_package: pkg ? pkg.toString() : "",
                                view_id: viewId ? viewId.toString() : ""
                            }
                        });
                    } catch(e) {}
                    return originalPerformAction.call(this, action);
                };
            } catch(err2) {}
        } catch(err) {}

        try {
            var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

            // 3. Hook performGlobalAction
            try {
                var originalPerformGlobal = AccessibilityService.performGlobalAction.overload("int");
                originalPerformGlobal.implementation = function(action) {
                    try {
                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "accessibility",
                            event_type: "ACCESSIBILITY_ACTION_PERFORMED",
                            timestamp_ms: Date.now(),
                            api: "android.accessibilityservice.AccessibilityService.performGlobalAction",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                global_action_code: action
                            }
                        });
                    } catch(e) {}
                    return originalPerformGlobal.call(this, action);
                };
            } catch(err3) {}
        } catch(err) {}
    });
})();
