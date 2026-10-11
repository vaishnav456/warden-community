FROM node:24-bookworm-slim AS dependencies
ENV NODE_ENV=production
WORKDIR /app
COPY cipher-db/package.json cipher-db/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY cipher-db/*.mjs ./
COPY third_party/licenses/npm/ ./third_party/licenses/npm/
FROM postgres:16-bookworm
COPY --from=dependencies /usr/local/bin/node /usr/local/bin/node
COPY --from=dependencies /app /app
WORKDIR /app
ENV NODE_ENV=production CIPHER_QUERY_ENGINE=native CIPHER_PROJECTION_ROOT=/run/warden-projection
RUN groupadd -g 10001 warden && useradd -u 10005 -g warden -M -s /usr/sbin/nologin warden-cipher
USER 10005:10001
ENTRYPOINT []
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=6s --start-period=120s --retries=3 CMD ["node", "healthcheck.mjs"]
CMD ["node", "start.mjs"]
