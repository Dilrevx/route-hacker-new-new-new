FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH
ENV MAVEN_OPTS="-Xmx2g -XX:+UseG1GC"

# Pre-configure Maven toolchain to use existing JDK 21 (avoids toolchains-maven-plugin JDK download)
RUN mkdir -p /root/.m2 && cat > /root/.m2/toolchains.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?>
<toolchains>
  <toolchain>
    <type>jdk</type>
    <provides>
      <version>21.0.1</version>
      <vendor>temurin</vendor>
    </provides>
    <configuration>
      <jdkHome>/usr/lib/jvm/temurin-21-jdk-amd64</jdkHome>
    </configuration>
  </toolchain>
</toolchains>
XML

COPY output/intermediates/iris-repos/crate__crate /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests clean package
