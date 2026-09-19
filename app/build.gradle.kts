plugins { id("com.android.application") }
android {
    namespace = "com.config.adblock"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.config.adblock"
        minSdk = 26
        targetSdk = 35
        versionCode = 101
        versionName = "0.6.0-content"
    }
    signingConfigs {
        create("release") {
            storeFile = file("cab.jks")
            storePassword = "cabpass123"
            keyAlias = "cab"
            keyPassword = "cabpass123"
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.getByName("release")
        }
        debug { applicationIdSuffix = ".debug" }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
dependencies {
    implementation(files("libs/mitm.aar"))
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.activity:activity-ktx:1.9.3")
}
