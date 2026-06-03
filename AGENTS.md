# AGENTS

- Single-module Android app; only module is `:app` (see `settings.gradle.kts`).
- App entrypoint is `com.example.pocketsshagent.MainActivity`, registered in `app/src/main/AndroidManifest.xml`.
- UI is Jetpack Compose; theme definitions live under `app/src/main/java/com/example/pocketsshagent/ui/theme/`.
- SDK levels are unusually high (`minSdk = 36`, `targetSdk = 36`) in `app/build.gradle.kts`.
- Dependency and plugin versions are managed via the version catalog at `gradle/libs.versions.toml`.
