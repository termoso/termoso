plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

val rustAbis: List<String> = (findProperty("termoso.abis") as String)
    .split(',')
    .map { it.trim() }
    .filter { it.isNotEmpty() }

// One version for the whole project: the workspace Cargo.toml is the source of truth
// (the desktop release workflow enforces the same for package.json).
val workspaceVersion: String = rootDir.parentFile.parentFile.resolve("Cargo.toml").useLines { lines ->
    lines.firstNotNullOfOrNull { Regex("""^version\s*=\s*"([^"]+)"""").find(it)?.groupValues?.get(1) }
} ?: error("workspace Cargo.toml has no version")

/** `MAJOR.MINOR.PATCH[-pre]` → `MMmmpp`; pre-release suffixes share the code of the final version. */
fun versionCodeOf(v: String): Int {
    val (major, minor, patch) = v.substringBefore('-').split('.').map { it.toInt() }
    require(minor < 100 && patch < 100) { "version $v does not fit MMmmpp" }
    return major * 10_000 + minor * 100 + patch
}

// Release signing comes from the environment only (CI secrets or a developer shell);
// nothing is read from the tree, so a checkout never contains key material.
val releaseKeystore: File? = System.getenv("TERMOSO_ANDROID_KEYSTORE")?.let(::File)?.takeIf { it.isFile }

// `-Ptermoso.splits=true` produces one APK per ABI plus a universal one (release workflow).
val abiSplits: Boolean = (findProperty("termoso.splits") as String?)?.toBoolean() ?: false

// Host whose https://<host>/invite/… and /join/… links open in the app (Android App Links).
// Must match the server publishing this build's signing certificate in /.well-known/assetlinks.json.
val appLinkHost: String = findProperty("termoso.appLinkHost") as String

android {
    namespace = "com.termoso.android"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.termoso.android"
        minSdk = 26
        targetSdk = 36
        versionCode = versionCodeOf(workspaceVersion)
        versionName = workspaceVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables.useSupportLibrary = true
        // Only ship the ABIs we build Rust for (JNA's AAR carries mips/armeabi too).
        ndk.abiFilters += rustAbis
        manifestPlaceholders["appLinkHost"] = appLinkHost
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = releaseKeystore
                storePassword = System.getenv("TERMOSO_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("TERMOSO_ANDROID_KEY_ALIAS") ?: "termoso"
                keyPassword = System.getenv("TERMOSO_ANDROID_KEY_PASSWORD") ?: System.getenv("TERMOSO_ANDROID_KEYSTORE_PASSWORD")
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            // Without TERMOSO_ANDROID_KEYSTORE the APK is left unsigned (app-release-unsigned.apk)
            // rather than silently signed with the debug key.
            signingConfig = signingConfigs.findByName("release")
        }
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
    }

    if (abiSplits) {
        splits.abi {
            isEnable = true
            reset()
            include(*rustAbis.toTypedArray())
            isUniversalApk = true
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlin {
        jvmToolchain(17)
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }

    packaging {
        resources.excludes += setOf("META-INF/AL2.0", "META-INF/LGPL2.1")
        // proot is exec'd from the native-library dir, so the .so files must be extracted to disk.
        jniLibs.useLegacyPackaging = true
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        disable += setOf("OldTargetApi")
    }

    // Reproducible, dependency-free: no Google Play services, no analytics.
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
}

dependencies {
    implementation(project(":core"))

    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.browser)

    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)
    implementation(libs.androidsvg)
    // QR import: on-device scanning only (bundled model, no network).
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.mlkit.barcode.scanning)
    debugImplementation(libs.compose.ui.tooling)
    debugImplementation(libs.compose.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.robolectric)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.compose.bom))
    androidTestImplementation(libs.compose.ui.test.junit4)
}
