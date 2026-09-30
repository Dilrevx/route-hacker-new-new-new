FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN apt-get update -qq && apt-get install -y ant ant-optional
RUN mkdir -p /root/.zcs-deps /root/.ivy2/cache \
    && wget -q https://files.zimbra.com/repository/ant-contrib/ant-contrib-1.0b1.jar -O /root/.zcs-deps/ant-contrib-1.0b1.jar \
    && wget -q https://files.zimbra.com/repository/ant-1.7.0-ziputil-patched/ant-1.7.0-ziputil-patched-1.0.jar -O /root/.zcs-deps/ant-1.7.0-ziputil-patched-1.0.jar \
    && git config --global --add safe.directory /workspace/repo

COPY output/intermediates/benchmark-repos/Zimbra__zm-mailbox /workspace/repo
WORKDIR /workspace/repo
RUN ant -Dzimbra.buildinfo.version=1.1.1_GA_1000 all
