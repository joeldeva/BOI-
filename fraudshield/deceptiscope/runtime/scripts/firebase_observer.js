/**
 * Safe observational Frida hook for Firebase / Firestore runtime communications.
 * Emits structured deceptiscope.runtime.v1 events without modifying data or sending network traffic.
 */

'use strict';

Java.perform(function () {
    // 1. Hook FirebaseDatabase (Realtime DB)
    try {
        var FirebaseDatabase = Java.use('com.google.firebase.database.FirebaseDatabase');
        FirebaseDatabase.getReference.overload('java.lang.String').implementation = function (path) {
            send({
                schema_version: 'deceptiscope.runtime.v1',
                timestamp_ms: Date.now(),
                event_type: 'firebase_database_reference',
                trust_level: 'INSTRUMENTED',
                process: Process.id,
                description: 'Firebase Realtime Database accessed reference: ' + path,
                api: 'com.google.firebase.database.FirebaseDatabase.getReference(String)',
                metadata: {
                    reference_path: path
                }
            });
            return this.getReference(path);
        };
    } catch (e) {
        // Class not present in this APK
    }

    // 2. Hook FirebaseFirestore (Cloud Firestore)
    try {
        var FirebaseFirestore = Java.use('com.google.firebase.firestore.FirebaseFirestore');
        FirebaseFirestore.collection.overload('java.lang.String').implementation = function (collectionPath) {
            send({
                schema_version: 'deceptiscope.runtime.v1',
                timestamp_ms: Date.now(),
                event_type: 'firebase_firestore_collection',
                trust_level: 'INSTRUMENTED',
                process: Process.id,
                description: 'Cloud Firestore accessed collection: ' + collectionPath,
                api: 'com.google.firebase.firestore.FirebaseFirestore.collection(String)',
                metadata: {
                    collection_path: collectionPath
                }
            });
            return this.collection(collectionPath);
        };
    } catch (e) {
        // Class not present in this APK
    }
});
