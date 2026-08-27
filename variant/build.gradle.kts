plugins { id("com.android.application") }

android {
    namespace = "in.trinetra.validation.core"
    compileSdk = 35
    defaultConfig {
        applicationId = "in.trinetra.validation.variant"
        minSdk = 23
        targetSdk = 28
        versionCode = 2
        versionName = "1.1-variant"
        buildConfigField("String", "VARIANT_NAME", "\"VARIANT\"")
    }
    buildFeatures { buildConfig = true }
    sourceSets["main"].java.srcDir("../shared/src/main/java")
}

dependencies { implementation("com.squareup.okhttp3:okhttp:4.12.0") }
