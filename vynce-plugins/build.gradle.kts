plugins {
    id("java")
}

group = "dev.ua.ikeepcalm.vynce.plugins"
version = "1.0.0"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    // Depend on the main project to access VulnerabilityTest interface
    implementation(project(":"))
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    compileOnly("org.projectlombok:lombok:1.18.42")
    annotationProcessor("org.projectlombok:lombok:1.18.42")
}

tasks.withType<JavaCompile> {
    options.encoding = "UTF-8"
}
