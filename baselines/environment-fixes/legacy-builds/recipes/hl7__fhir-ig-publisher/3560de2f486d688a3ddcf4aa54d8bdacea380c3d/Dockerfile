FROM route-hacker-base:tools-78932d2e

# JDK 11 required (maven.compiler.release=11)
ENV JAVA_HOME=/usr/lib/jvm/temurin-11-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Fix Maven settings (remove unreachable proxy, use Maven Central directly)
RUN mkdir -p /root/.m2 && echo '<settings><mirrors><mirror><id>central-direct</id><mirrorOf>central</mirrorOf><url>https://repo1.maven.org/maven2</url></mirror></mirrors></settings>' > /root/.m2/settings.xml

# Mark repo directory as safe for git (buildnumber-maven-plugin needs git log)
RUN git config --global --add safe.directory /workspace/repo

COPY hl7__fhir-ig-publisher /workspace/repo
WORKDIR /workspace/repo

# Patch SNAPSHOT dependency to use released version (6.4.2-SNAPSHOT unavailable remotely)
RUN sed -i 's/<core_version>6.4.2-SNAPSHOT/<core_version>6.4.2/' pom.xml

# Build (skip tests, skip javadoc which has encoding issues on non-UTF-8 locales)
RUN mvn -B -DskipTests -Dmaven.javadoc.skip=true install
