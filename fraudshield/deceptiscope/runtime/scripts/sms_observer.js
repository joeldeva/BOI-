// DeceptiScope Defensive SMS Observer
// Observes raw SMS parsing and transmission hooks safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        try {
            var SmsMessage = Java.use("android.telephony.SmsMessage");

            // 1. Hook createFromPdu(byte[])
            try {
                var originalCreateFromPdu1 = SmsMessage.createFromPdu.overload("[B");
                originalCreateFromPdu1.implementation = function(pdu) {
                    var result = originalCreateFromPdu1.call(this, pdu);
                    try {
                        var body = result ? (result.getMessageBody() || "") : "";
                        var sender = result ? (result.getOriginatingAddress() || "") : "";
                        var strBody = body ? body.toString() : "";
                        var hasSyntheticMarker = (strBody.indexOf("DS-TEST-") !== -1 || strBody.indexOf("BOI-TEST-") !== -1 || strBody.indexOf("OTP") !== -1);

                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "sms",
                            event_type: "SMS_PDU_PARSED",
                            timestamp_ms: Date.now(),
                            api: "android.telephony.SmsMessage.createFromPdu([B)",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                sender: sender ? sender.toString() : "",
                                body_length: strBody.length,
                                has_synthetic_marker: hasSyntheticMarker,
                                preview: strBody.length > 50 ? strBody.substring(0, 50) + "..." : strBody
                            }
                        });
                    } catch(e) {}
                    return result;
                };
            } catch(err1) {}

            // 2. Hook createFromPdu(byte[], String)
            try {
                var originalCreateFromPdu2 = SmsMessage.createFromPdu.overload("[B", "java.lang.String");
                originalCreateFromPdu2.implementation = function(pdu, format) {
                    var result = originalCreateFromPdu2.call(this, pdu, format);
                    try {
                        var body = result ? (result.getMessageBody() || "") : "";
                        var sender = result ? (result.getOriginatingAddress() || "") : "";
                        var strBody = body ? body.toString() : "";
                        var hasSyntheticMarker = (strBody.indexOf("DS-TEST-") !== -1 || strBody.indexOf("BOI-TEST-") !== -1 || strBody.indexOf("OTP") !== -1);

                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "sms",
                            event_type: "SMS_PDU_PARSED",
                            timestamp_ms: Date.now(),
                            api: "android.telephony.SmsMessage.createFromPdu([B, String)",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                sender: sender ? sender.toString() : "",
                                format: format ? format.toString() : "",
                                body_length: strBody.length,
                                has_synthetic_marker: hasSyntheticMarker,
                                preview: strBody.length > 50 ? strBody.substring(0, 50) + "..." : strBody
                            }
                        });
                    } catch(e) {}
                    return result;
                };
            } catch(err2) {}
        } catch(err) {}

        try {
            var SmsManager = Java.use("android.telephony.SmsManager");

            // 3. Hook sendTextMessage
            try {
                var originalSendTextMessage = SmsManager.sendTextMessage.overload("java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent");
                originalSendTextMessage.implementation = function(dest, sc, text, sent, deliv) {
                    try {
                        var strText = text ? text.toString() : "";
                        var hasSyntheticMarker = (strText.indexOf("DS-TEST-") !== -1 || strText.indexOf("BOI-TEST-") !== -1);

                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "sms",
                            event_type: "SMS_SEND_ATTEMPT",
                            timestamp_ms: Date.now(),
                            api: "android.telephony.SmsManager.sendTextMessage",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                destination: dest ? dest.toString() : "",
                                text_length: strText.length,
                                has_synthetic_marker: hasSyntheticMarker,
                                preview: strText.length > 50 ? strText.substring(0, 50) + "..." : strText
                            }
                        });
                    } catch(e) {}
                    return originalSendTextMessage.call(this, dest, sc, text, sent, deliv);
                };
            } catch(err3) {}
        } catch(err) {}
    });
})();
