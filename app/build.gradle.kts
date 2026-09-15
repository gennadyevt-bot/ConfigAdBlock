plugins { id("com.android.application") }
android {
    namespace = "com.config.adblock"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.config.adblock"
        minSdk = 26
        targetSdk = 35
        versionCode = 7
        versionName = "0.2.3"
    }
    buildTypes {
        release { isMinifyEnabled = false }
        debug { applicationIdSuffix = ".debug" }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
}
