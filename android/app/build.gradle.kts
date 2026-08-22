plugins {
    id("com.android.application")
}

android {
    namespace = "world.w3b.kdbxfortress"
    compileSdk = 37

    defaultConfig {
        applicationId = "world.w3b.kdbxfortress"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0-dev"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    implementation(project(":native-bridge"))
}
