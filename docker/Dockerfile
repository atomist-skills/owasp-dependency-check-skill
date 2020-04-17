FROM owasp/dependency-check

WORKDIR /usr/src/app

COPY package*.json /usr/src/app/
RUN npm ci \
    && npm cache clean --force

COPY deps.edn shadow-cljs.edn /usr/src/app/
COPY src /usr/src/app/src
RUN npm run build \
    && rm -rf .cpcache .shadow-cljs

ENTRYPOINT [ "node" ]
CMD [ "index.js" ]