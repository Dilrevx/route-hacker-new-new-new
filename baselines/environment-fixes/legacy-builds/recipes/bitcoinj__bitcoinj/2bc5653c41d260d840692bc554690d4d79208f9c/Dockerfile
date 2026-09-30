FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Install Gradle 7.6.3
RUN curl -sL https://services.gradle.org/distributions/gradle-7.6.3-bin.zip -o /tmp/gradle.zip && \
    unzip -q /tmp/gradle.zip -d /opt && \
    ln -sf /opt/gradle-7.6.3/bin/gradle /usr/local/bin/gradle && \
    rm /tmp/gradle.zip

COPY bitcoinj__bitcoinj /workspace/repo
WORKDIR /workspace/repo
RUN gradle build -x test --no-daemon
