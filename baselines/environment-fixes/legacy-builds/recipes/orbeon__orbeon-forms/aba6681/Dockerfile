FROM route-hacker-base:tools-78932d2e

ENV HTTP_PROXY=http://127.0.0.1:7890
ENV HTTPS_PROXY=http://127.0.0.1:7890
ENV JAVA_HOME=/opt/zulu7.56.0.11-ca-jdk7.0.352-linux_x64
ENV PATH=$JAVA_HOME/bin:$PATH

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt \
    && cd /opt \
    && curl -fsSLo zulu7.tar.gz https://cdn.azul.com/zulu/bin/zulu7.56.0.11-ca-jdk7.0.352-linux_x64.tar.gz \
    && tar -xzf zulu7.tar.gz \
    && rm zulu7.tar.gz

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y ant \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/ant-1.9.16 \
    && cd /opt/ant-1.9.16 \
    && curl -fsSLO https://repo.maven.apache.org/maven2/org/apache/ant/ant/1.9.16/ant-1.9.16.jar \
    && curl -fsSLO https://repo.maven.apache.org/maven2/org/apache/ant/ant-launcher/1.9.16/ant-launcher-1.9.16.jar

COPY output/intermediates/benchmark-repos/orbeon__orbeon-forms /workspace/repo
WORKDIR /workspace/repo

RUN java -cp /opt/ant-1.9.16/ant-1.9.16.jar:/opt/ant-1.9.16/ant-launcher-1.9.16.jar org.apache.tools.ant.launch.Launcher orbeon-war
