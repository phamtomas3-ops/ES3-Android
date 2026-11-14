plugins { alias(libs.plugins.kotlin.jvm); `java-library` }
kotlin { jvmToolchain(17) }
dependencies {
    api(project(":core:common"))
    api(project(":core:crypto"))
    testImplementation(kotlin("test"))
}
tasks.test {
    useJUnitPlatform()
    // Deliberately small heap: the streaming-memory test pushes more data than fits in it.
    maxHeapSize = "160m"
    testLogging { events("passed", "failed", "skipped"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}
