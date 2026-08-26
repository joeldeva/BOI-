// DeceptiScope Defensive Accessibility Observer
// Observes UI text harvesting and action injection hooks safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        try {
            var AccessibilityNodeInfo = Java.use("android.view.accessibility.AccessibilityNodeInfo");

            // Hook getText()
            AccessibilityNodeInfo.getText.implementation = function() {
                var text = this.getText();
                try {
                    var strText = text ? text.toString() : "";
                    var viewId = (this.getViewIdResourceName() || "");
                    var pkg = (this.getPackageName() || "");
                    var hasSyntheticMarker = (strText.indexOf("BOI-TEST-") !== -1 || strText.indexOf("OTP") !== -1);

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
                            preview: strText.length > 30 ? strText.substring(0, 30) + "..." : strText
                        }
                    });
                } catch(e) {}
                return text;
            };

            // Hook performAction(int)
            AccessibilityNodeInfo.performAction.overload("int").implementation = function(action) {
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
                return this.performAction(action);
            };
        } catch(err) {}

        try {
            var AccessibilityService = Java.use("android.accessibilityservice.AccessibilityService");

            // Hook performGlobalAction
            AccessibilityService.performGlobalAction.implementation = function(action) {
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
                return this.performGlobalAction(action);
            };
        } catch(err) {}
    });
})();
