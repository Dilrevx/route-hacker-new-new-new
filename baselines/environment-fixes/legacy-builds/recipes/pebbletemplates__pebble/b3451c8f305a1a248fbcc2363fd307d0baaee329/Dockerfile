FROM route-hacker-base:tools-78932d2e

ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Configure Maven settings with aliyun mirror, no proxy
RUN mkdir -p /root/.m2 && \
    printf '%s\n' '<settings><mirrors><mirror><id>aliyun-central</id><mirrorOf>central</mirrorOf><url>https://maven.aliyun.com/repository/central</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

COPY pebbletemplates__pebble /workspace/repo

WORKDIR /workspace/repo

# Write clean parent POM (removed: pebble-spring/docs modules, central-publishing plugin, spring-milestones repos)
RUN printf '%s\n' '<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' > pom.xml && \
    printf '%s\n' '  <modelVersion>4.0.0</modelVersion>' >> pom.xml && \
    printf '%s\n' '  <groupId>io.pebbletemplates</groupId>' >> pom.xml && \
    printf '%s\n' '  <artifactId>pebble-project</artifactId>' >> pom.xml && \
    printf '%s\n' '  <version>4.1.0-SNAPSHOT</version>' >> pom.xml && \
    printf '%s\n' '  <packaging>pom</packaging>' >> pom.xml && \
    printf '%s\n' '  <modules>' >> pom.xml && \
    printf '%s\n' '    <module>pebble</module>' >> pom.xml && \
    printf '%s\n' '  </modules>' >> pom.xml && \
    printf '%s\n' '  <name>Pebble Project</name>' >> pom.xml && \
    printf '%s\n' '  <description>Pebble Project</description>' >> pom.xml && \
    printf '%s\n' '  <url>http://pebbletemplates.io</url>' >> pom.xml && \
    printf '%s\n' '  <properties>' >> pom.xml && \
    printf '%s\n' '    <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>' >> pom.xml && \
    printf '%s\n' '    <java.version>1.8</java.version>' >> pom.xml && \
    printf '%s\n' '  </properties>' >> pom.xml && \
    printf '%s\n' '  <build>' >> pom.xml && \
    printf '%s\n' '    <plugins>' >> pom.xml && \
    printf '%s\n' '      <plugin>' >> pom.xml && \
    printf '%s\n' '        <artifactId>maven-compiler-plugin</artifactId>' >> pom.xml && \
    printf '%s\n' '        <version>3.14.1</version>' >> pom.xml && \
    printf '%s\n' '        <configuration>' >> pom.xml && \
    printf '%s\n' '          <source>${java.version}</source>' >> pom.xml && \
    printf '%s\n' '          <target>${java.version}</target>' >> pom.xml && \
    printf '%s\n' '          <parameters>true</parameters>' >> pom.xml && \
    printf '%s\n' '        </configuration>' >> pom.xml && \
    printf '%s\n' '      </plugin>' >> pom.xml && \
    printf '%s\n' '    </plugins>' >> pom.xml && \
    printf '%s\n' '  </build>' >> pom.xml && \
    printf '%s\n' '</project>' >> pom.xml && \
    mvn -B -DskipTests compile -pl pebble
