FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV http_proxy=http://127.0.0.1:7890
ENV https_proxy=http://127.0.0.1:7890
ENV JAVA_HOME=/usr/lib/jvm/temurin-8-jdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN printf 'Acquire::http::Proxy "http://127.0.0.1:7890";\nAcquire::https::Proxy "http://127.0.0.1:7890";\nAcquire::https::Verify-Peer "false";\nAcquire::https::Verify-Host "false";\n' > /etc/apt/apt.conf.d/99proxy \
    && apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ant ant-contrib \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /root/.ivy2/cache /root/.zcs-deps

RUN git config --global --add safe.directory /workspace/repo

COPY output/intermediates/benchmark-repos/Zimbra__zm-mailbox /workspace/repo
WORKDIR /workspace/repo

RUN ant -Dzimbra.buildinfo.version=8.8.15_GA_1 all
