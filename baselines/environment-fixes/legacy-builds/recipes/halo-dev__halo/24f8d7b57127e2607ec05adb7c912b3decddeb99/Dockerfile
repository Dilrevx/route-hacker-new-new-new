FROM route-hacker-temp/halo-gradle-cache

RUN rm -rf /workspace/repo

COPY halo-dev__halo /workspace/repo
WORKDIR /workspace/repo
RUN ./gradlew build -x test -x checkstyleMain -x checkstyleTest -x jacocoTestReport --no-daemon
