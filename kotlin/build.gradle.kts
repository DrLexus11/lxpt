// lxpt for the JVM and Android: pure Kotlin, no Android dependency, no runtime
// dependency beyond the Kotlin standard library. Published through JitPack as
// com.github.DrLexus11:lxpt:<tag> (jitpack.yml at the repository root).

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.2.21"
    `java-library`
    `maven-publish`
}

group = "com.github.DrLexus11"
if (version == Project.DEFAULT_VERSION) version = "0.3.0-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
    withSourcesJar()
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
        allWarningsAsErrors.set(true)
    }
}

dependencies {
    testImplementation(kotlin("test"))
    testImplementation(platform("org.junit:junit-bom:5.11.4"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("lxpt.fixture", rootProject.file("../fixtures/lxpt_wire_v1.json").absolutePath)
    testLogging {
        events("passed", "failed")
        showStandardStreams = true
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            artifactId = "lxpt"
            from(components["java"])
            pom {
                name.set("lxpt")
                description.set("Lightweight Extensible Push-to-Talk: wire codecs and floor and relay cores for group talk channels over Reticulum")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
            }
        }
    }
}
