// The Android Gradle plugin pulls Guava 33.4 onto the build classpath;
// GitHub flags every Guava below 33.7.2. Build-time only, pinned here so
// the dependency graph stops reporting it until AGP catches up.
buildscript {
    dependencies {
        constraints {
            classpath("com.google.guava:guava:33.7.2-jre") {
                because("Dependabot high alert on the AGP build classpath")
            }
        }
    }
}

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.compose) apply false
}

// Lint (com.android.tools.lint) and Robolectric still request older Guava on
// their own configurations; lift every request so the dependency graph
// carries a single patched version.
subprojects {
    configurations.configureEach {
        resolutionStrategy.eachDependency {
            if (requested.group == "com.google.guava" && requested.name == "guava") {
                useVersion("33.7.2-jre")
                because("Dependabot high alert; build/test classpath only")
            }
        }
    }
}
