// DeceptiScope Defensive Dynamic DEX Observer
// Observes runtime secondary DEX class loading safely
(function() {
    if (!Java.available) return;

    Java.perform(function() {
        // 1. DexClassLoader.<init>
        try {
            var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
            var originalDexInit = DexClassLoader.$init.overload("java.lang.String", "java.lang.String", "java.lang.String", "java.lang.ClassLoader");
            originalDexInit.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
                try {
                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "dynamic_dex",
                        event_type: "DEX_CLASS_LOADER_INIT",
                        timestamp_ms: Date.now(),
                        api: "dalvik.system.DexClassLoader.<init>",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            loader_type: "DexClassLoader",
                            dex_path: dexPath ? dexPath.toString() : "",
                            opt_dir: optimizedDirectory ? optimizedDirectory.toString() : "",
                            lib_search_path: librarySearchPath ? librarySearchPath.toString() : ""
                        }
                    });
                } catch(e) {}
                return originalDexInit.call(this, dexPath, optimizedDirectory, librarySearchPath, parent);
            };
        } catch(err1) {}

        // 2. InMemoryDexClassLoader.<init>
        try {
            var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
            var originalInMemoryInit = InMemoryDexClassLoader.$init.overload("java.nio.ByteBuffer", "java.lang.ClassLoader");
            originalInMemoryInit.implementation = function(buffer, parent) {
                try {
                    var capacity = buffer ? buffer.capacity() : 0;
                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "dynamic_dex",
                        event_type: "IN_MEMORY_DEX_LOADED",
                        timestamp_ms: Date.now(),
                        api: "dalvik.system.InMemoryDexClassLoader.<init>(ByteBuffer)",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            loader_type: "InMemoryDexClassLoader",
                            buffer_capacity_bytes: capacity
                        }
                    });
                } catch(e) {}
                return originalInMemoryInit.call(this, buffer, parent);
            };
        } catch(err2) {}

        // 3. DexFile.loadDex
        try {
            var DexFile = Java.use("dalvik.system.DexFile");
            var originalLoadDex = DexFile.loadDex.overload("java.lang.String", "java.lang.String", "int");
            originalLoadDex.implementation = function(sourcePathName, outputPathName, flags) {
                try {
                    send({
                        schema: "deceptiscope.runtime.v1",
                        observer: "dynamic_dex",
                        event_type: "DEX_FILE_LOADED",
                        timestamp_ms: Date.now(),
                        api: "dalvik.system.DexFile.loadDex",
                        target_package: (Java.use("android.app.ActivityThread").currentPackageName() || "target.app"),
                        metadata: {
                            source_path: sourcePathName ? sourcePathName.toString() : "",
                            output_path: outputPathName ? outputPathName.toString() : "",
                            flags: flags
                        }
                    });
                } catch(e) {}
                return originalLoadDex.call(this, sourcePathName, outputPathName, flags);
            };
        } catch(err3) {}
    });
})();
