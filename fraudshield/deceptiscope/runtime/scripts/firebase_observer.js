/**
 * Safe observational Frida hook for Firebase / Firestore runtime communications.
 * Emits structured deceptiscope.runtime.v1 events without modifying data or sending network traffic.
 */

'use strict';

Java.perform(function () {
    // 1. Hook FirebaseDatabase (Realtime DB)
    try {
        var FirebaseDatabase = Java.use('com.google.firebase.database.FirebaseDatabase');
        var originalGetRef = FirebaseDatabase.getReference.overload('java.lang.String');
        originalGetRef.implementation = function (path) {
            try {
                send({
                    schema: 'deceptiscope.runtime.v1',
                    observer: 'network',
                    event_type: 'HTTP_REQUEST_OBSERVED',
                    timestamp_ms: Date.now(),
                    api: 'com.google.firebase.database.FirebaseDatabase.getReference(String)',
                    target_package: (Java.use('android.app.ActivityThread').currentPackageName() || 'target.app'),
                    metadata: {
                        client: 'FirebaseDatabase',
                        reference_path: path ? path.toString() : '',
                        has_synthetic_marker: false
                    }
                });
            } catch(e) {}
            return originalGetRef.call(this, path);
        };
    } catch (e) {
        // Class not present in this APK
    }

    // 2. Hook FirebaseFirestore (Cloud Firestore)
    try {
        var FirebaseFirestore = Java.use('com.google.firebase.firestore.FirebaseFirestore');
        var originalCollection = FirebaseFirestore.collection.overload('java.lang.String');
        originalCollection.implementation = function (collectionPath) {
            try {
                send({
                    schema: 'deceptiscope.runtime.v1',
                    observer: 'network',
                    event_type: 'HTTP_REQUEST_OBSERVED',
                    timestamp_ms: Date.now(),
                    api: 'com.google.firebase.firestore.FirebaseFirestore.collection(String)',
                    target_package: (Java.use('android.app.ActivityThread').currentPackageName() || 'target.app'),
                    metadata: {
                        client: 'FirebaseFirestore',
                        collection_path: collectionPath ? collectionPath.toString() : '',
                        has_synthetic_marker: false
                    }
                });
            } catch(e) {}
            return originalCollection.call(this, collectionPath);
        };
    } catch (e) {
        // Class not present in this APK
    }
});
