FROM route-hacker-base:tools-78932d2e

# Project requires Java 1.8
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Remove the default proxy in settings.xml (points to a local proxy on Docker host)
RUN rm -f /root/.m2/settings.xml

COPY ycf1998__money-pos /workspace/repo
WORKDIR /workspace/repo/money-pos
RUN mvn -B -DskipTests compile
