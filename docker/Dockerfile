# hadolint ignore=DL3007
FROM owasp/dependency-check:latest@sha256:185d5bb51a62831e95710afa46182694f656f98a4ba83d8ffcf50a5ffce60d78

USER root

ENV LEIN_VERSION=2.9.3
ENV LEIN_INSTALL=/usr/local/bin/
ENV LEIN_ROOT=1
ENV CLOJURE_VERSION=1.10.1.462

SHELL ["/bin/ash", "-o", "pipefail", "-c"]

RUN apk update && \
    apk add --update --no-cache ca-certificates bash curl tar openssl gnupg nodejs npm && \
    mkdir -p $LEIN_INSTALL && \
    wget -q https://raw.githubusercontent.com/technomancy/leiningen/$LEIN_VERSION/bin/lein-pkg && \
    echo "Comparing lein-pkg checksum ..." && \
    sha256sum lein-pkg && \
    echo "42e18e8a833b863ddfba1c5565bd5d78b54bcee661ec86e94a8bdc67b1733e63 *lein-pkg" | sha256sum -c - && \
    mv lein-pkg $LEIN_INSTALL/lein && \
    chmod 0755 $LEIN_INSTALL/lein && \
    wget -q https://github.com/technomancy/leiningen/releases/download/$LEIN_VERSION/leiningen-$LEIN_VERSION-standalone.zip && \
    mkdir -p /usr/share/java && \
    mv leiningen-$LEIN_VERSION-standalone.zip /usr/share/java/leiningen-$LEIN_VERSION-standalone.jar && \
    wget -q https://download.clojure.org/install/linux-install-$CLOJURE_VERSION.sh && \
    chmod +x linux-install-$CLOJURE_VERSION.sh && \
    ./linux-install-$CLOJURE_VERSION.sh && \
    apk del ca-certificates tar openssl gnupg curl

WORKDIR /tmp

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/bin/:/opt/jdk/bin

ENV JAVA_HOME=/opt/jdk

RUN echo '(defproject dummy "" :dependencies [[org.clojure/clojure "1.10.1"]])' > project.clj && lein deps && rm project.clj

WORKDIR /usr/src/app
# TODO run as USER dependencycheck

COPY package*.json /usr/src/app/
RUN npm ci \
    && npm cache clean --force

COPY deps.edn shadow-cljs.edn /usr/src/app/
COPY src /usr/src/app/src
RUN npm run build \
    && rm -rf .cpcache .shadow-cljs

ENV JDBC_DRIVER_PATH=/root/.m2/repository/mysql/mysql-connector-java/8.0.21/mysql-connector-java-8.0.21.jar
ENV DEPENDENCY_CHECK=/usr/share/dependency-check/bin/dependency-check.sh

ENTRYPOINT [ "node" ]
CMD [ "index.js" ]
