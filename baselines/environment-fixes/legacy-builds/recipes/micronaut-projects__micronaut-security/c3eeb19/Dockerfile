FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=7890\nsystemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=7890\n' > /root/.gradle/gradle.properties

COPY output/intermediates/benchmark-repos/micronaut-projects__micronaut-security /workspace/repo

WORKDIR /workspace/repo

RUN perl -0pi -e "s/repositories \\{\\n        gradlePluginPortal\\(\\)\\n        mavenCentral\\(\\)\\n    \\}/repositories {\\n        gradlePluginPortal()\\n        mavenCentral()\\n        maven { url 'https:\\/\\/repo.grails.org\\/grails\\/core' }\\n    }/" settings.gradle && ./gradlew --no-daemon --console=plain compileJava
