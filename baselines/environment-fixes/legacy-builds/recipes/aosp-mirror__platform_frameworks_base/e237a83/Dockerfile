FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=/opt/android-sdk
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN mkdir -p /root/.gradle && printf 'systemProp.http.proxyHost=127.0.0.1\nsystemProp.http.proxyPort=7890\nsystemProp.https.proxyHost=127.0.0.1\nsystemProp.https.proxyPort=7890\n' > /root/.gradle/gradle.properties

RUN set -eux; \
    mkdir -p /opt/android-sdk/cmdline-tools; \
    cd /tmp; \
    curl -L --retry 5 --retry-delay 2 -o cmdline-tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip; \
    unzip -q cmdline-tools.zip -d /opt/android-sdk/cmdline-tools; \
    mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest; \
    export JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64; \
    export PATH=$JAVA_HOME/bin:$PATH; \
    yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk --licenses >/dev/null || true; \
    /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --sdk_root=/opt/android-sdk "platform-tools" "platforms;android-28" "build-tools;28.0.3"

COPY output/intermediates/benchmark-repos/aosp-mirror__platform_frameworks_base /workspace/repo
RUN printf 'sdk.dir=/opt/android-sdk\n' > /workspace/repo/tests/TouchLatency/local.properties

WORKDIR /workspace/repo/tests/TouchLatency
RUN ./gradlew --no-daemon :app:assembleDebug
