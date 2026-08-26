// DeceptiScope Defensive Notification Observer
// Observes notification access and listener callbacks safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        try {
            var NotificationListenerService = Java.use("android.service.notification.NotificationListenerService");

            NotificationListenerService.onNotificationPosted.overload("android.service.notification.StatusBarNotification").implementation = function(sbn) {
                try {
                    var pkg = sbn ? sbn.getPackageName() : "unknown";
                    var notification = sbn ? sbn.getNotification() : null;
                    var extras = notification ? notification.extras.value : null;
                    var title = extras ? (extras.getString("android.title") || "") : "";
                    var text = extras ? (extras.getCharSequence("android.text") || "") : "";
                    var strText = text ? text.toString() : "";
                    var hasSyntheticMarker = (strText.indexOf("BOI-TEST-") !== -1 || strText.indexOf("OTP") !== -1);

                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "notification",
                        event_type: "NOTIFICATION_TEXT_READ",
                        timestamp_ms: Date.now(),
                        api: "android.service.notification.NotificationListenerService.onNotificationPosted",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            source_package: pkg,
                            title_length: title ? title.length : 0,
                            has_synthetic_marker: hasSyntheticMarker,
                            preview: strText.length > 30 ? strText.substring(0, 30) + "..." : strText
                        }
                    });
                } catch(e) {}
                return this.onNotificationPosted(sbn);
            };
        } catch(err) {}
    });
})();
