plugins { id("com.android.application") }

android {
    namespace = "in.trinetra.validation.core"
    compileSdk = 35
    defaultConfig {
        applicationId = "in.trinetra.validation"
        minSdk = 23
        targetSdk = 28
        versionCode = 1
        versionName = "1.0"
        buildConfigField("String", "VARIANT_NAME", "\"VALIDATION\"")
    }
    buildFeatures { buildConfig = true }
    sourceSets["main"].java.srcDir("../shared/src/main/java")
}

dependencies { implementation("com.squareup.okhttp3:okhttp:4.12.0") }
