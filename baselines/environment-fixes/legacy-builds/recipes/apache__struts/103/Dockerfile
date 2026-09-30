FROM route-hacker-base:tools-78932d2e-iris
ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
# JDK 8 for source/target 1.7 compatibility
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:/opt/maven-3.5.0/bin:$PATH
# Replace wget with a timeout wrapper to avoid hanging on slow doc downloads
RUN mv /usr/bin/wget /usr/bin/wget.orig && \
    printf '#!/bin/bash\nexec /usr/bin/wget.orig --timeout=15 --tries=2 "$@"\n' > /usr/bin/wget && \
    chmod +x /usr/bin/wget
COPY output/intermediates/iris-repos/apache__struts /workspace/repo
WORKDIR /workspace/repo
RUN mvn -B -DskipTests package
