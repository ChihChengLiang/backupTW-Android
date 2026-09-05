plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "tw.bonds.backuptw.wallet"
    compileSdk = 34

    defaultConfig {
        applicationId = "tw.bonds.backuptw.wallet"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation("net.java.dev.jna:jna:5.14.0@aar")

    val composeBom = platform("androidx.compose:compose-bom:2024.09.00")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.activity:activity-compose:1.9.2")

    // Networking: real TWDIW/Arbitrum HTTP calls (see docs/2026-09-05-*
    // field notes for the exact endpoints). Standard, well-tested; avoids
    // hand-rolling HttpURLConnection boilerplate across ~10 call sites.
    implementation("com.squareup.okhttp3:okhttp:4.12.0")

    // Encrypted at-rest storage for received credentials and offline
    // issuer trust snapshots - both are sensitive (a credential carries a
    // name and phone number once disclosed; a snapshot names an issuer
    // this device trusted).
    implementation("androidx.security:security-crypto:1.1.0-alpha06")

    // Explicit rather than relying on Compose's transitive version, so
    // network calls can be dispatched to Dispatchers.IO deliberately.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")
}
