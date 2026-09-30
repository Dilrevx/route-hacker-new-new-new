FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-17-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN git config --global --add safe.directory /workspace/repo \
    && git config --global --add safe.directory /workspace/repo/graylog2-server

COPY output/intermediates/benchmark-repos/Graylog2__graylog2-server /workspace/repo

WORKDIR /workspace/repo

RUN ./mvnw -B -DskipTests -Dskip.web.build compile
