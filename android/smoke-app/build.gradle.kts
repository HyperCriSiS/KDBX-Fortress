plugins {
    id("com.android.application")
}

android {
    namespace = "world.w3b.kdbxfortress.smoke"
    compileSdk = 37

    defaultConfig {
        applicationId = "world.w3b.kdbxfortress.smoke"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.0.0-smoke"
    }

    buildTypes {
        debug {
            isDebuggable = true
        }
    }

    sourceSets {
        getByName("main") {
            assets.srcDir("../../test-fixtures/kdbx")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
