plugins {
  id("com.android.application")
  id("org.jetbrains.kotlin.android")
}

android {
  namespace = "dev.caturma.testauthenticator"
  compileSdk = 35

  defaultConfig {
    applicationId = "dev.caturma.testauthenticator"
    /* Credential providers are Android 14. There is no shim for this and
       there should not be one: the whole point is the platform API. */
    minSdk = 34
    targetSdk = 35
    versionCode = 1
    versionName = "0.1.0"
  }

  buildTypes {
    debug {
      /* Auto-approve is compiled in only here. A release build of a thing
         that consents to itself has no honest use. */
      buildConfigField("boolean", "ALLOW_AUTO_APPROVE", "true")
    }
    release {
      isMinifyEnabled = false
      buildConfigField("boolean", "ALLOW_AUTO_APPROVE", "false")
    }
  }

  buildFeatures { buildConfig = true }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
  }
  kotlinOptions { jvmTarget = "17" }
}

dependencies {
  implementation("androidx.credentials:credentials:1.3.0")
  implementation("androidx.core:core-ktx:1.13.1")
  implementation("androidx.appcompat:appcompat:1.7.0")

  /* The ceremony half has no Android in it on purpose -- see Ceremony.kt --
     so the bytes a verifier reads can be checked on a JVM, in a second,
     rather than by driving an emulator by hand. */
  testImplementation("junit:junit:4.13.2")
  /* The real org.json. Android ships one, but the unit-test android.jar is
     a stub whose every method answers null -- so without this the JSON in
     a response comes out empty and the assertions pass against nothing. */
  testImplementation("org.json:json:20240303")
}
