FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890

# Set correct JAVA_HOME for JDK 11
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.9.8/bin:$PATH

COPY output/intermediates/iris-repos/xwiki__xwiki-commons /workspace/repo
WORKDIR /workspace/repo

# Clean Maven repo to avoid corrupted artifacts, then install
RUN rm -rf /root/.m2/repository && mvn -B -DskipTests -U install
