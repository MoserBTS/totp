plugins {
    `java-library`
}

group = "com.github.MoserBTS"
version = "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    implementation("commons-codec:commons-codec:1.21.0")

}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(25)
    }

}