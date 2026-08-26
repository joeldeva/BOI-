// DeceptiScope Defensive SMS Observer
// Observes raw SMS parsing and transmission hooks safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        try {
            var SmsMessage = Java.use("android.telephony.SmsMessage");

            // Hook createFromPdu(byte[])
            SmsMessage.createFromPdu.overload("[B").implementation = function(pdu) {
                var result = this.createFromPdu(pdu);
                try {
                    var body = result ? (result.getMessageBody() || "") : "";
                    var sender = result ? (result.getOriginatingAddress() || "") : "";
                    var hasSyntheticMarker = (body.indexOf("BOI-TEST-") !== -1 || body.indexOf("OTP") !== -1);

                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "sms",
                        event_type: "SMS_PDU_PARSED",
                        timestamp_ms: Date.now(),
                        api: "android.telephony.SmsMessage.createFromPdu([B)",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            sender: sender,
                            body_length: body.length,
                            has_synthetic_marker: hasSyntheticMarker,
                            preview: body.length > 30 ? body.substring(0, 30) + "..." : body
                        }
                    });
                } catch(e) {}
                return result;
            };

            // Hook createFromPdu(byte[], String)
            if (SmsMessage.createFromPdu.overload("[B", "java.lang.String")) {
                SmsMessage.createFromPdu.overload("[B", "java.lang.String").implementation = function(pdu, format) {
                    var result = this.createFromPdu(pdu, format);
                    try {
                        var body = result ? (result.getMessageBody() || "") : "";
                        var sender = result ? (result.getOriginatingAddress() || "") : "";
                        var hasSyntheticMarker = (body.indexOf("BOI-TEST-") !== -1 || body.indexOf("OTP") !== -1);

                        send({
                            schema: "deceptiscope.runtime.v1",
                            observer: "sms",
                            event_type: "SMS_PDU_PARSED",
                            timestamp_ms: Date.now(),
                            api: "android.telephony.SmsMessage.createFromPdu([B, String)",
                            target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                            metadata: {
                                sender: sender,
                                format: format,
                                body_length: body.length,
                                has_synthetic_marker: hasSyntheticMarker,
                                preview: body.length > 30 ? body.substring(0, 30) + "..." : body
                            }
                        });
                    } catch(e) {}
                    return result;
                };
            }
        } catch(err) {}

        try {
            var SmsManager = Java.use("android.telephony.SmsManager");

            // Hook sendTextMessage
            SmsManager.sendTextMessage.overload("java.lang.String", "java.lang.String", "java.lang.String", "android.app.PendingIntent", "android.app.PendingIntent").implementation = function(dest, sc, text, sent, deliv) {
                try {
                    var strText = text ? text.toString() : "";
                    var hasSyntheticMarker = (strText.indexOf("BOI-TEST-") !== -1);

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
                            preview: strText.length > 30 ? strText.substring(0, 30) + "..." : strText
                        }
                    });
                } catch(e) {}
                return this.sendTextMessage(dest, sc, text, sent, deliv);
            };
        } catch(err) {}
    });
})();
