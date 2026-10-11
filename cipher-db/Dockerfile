FROM node:24-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY cipher-db/package.json cipher-db/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force
COPY cipher-db/*.mjs ./
COPY third_party/licenses/npm/ ./third_party/licenses/npm/
RUN groupadd -g 10001 warden && useradd -u 10005 -g warden -M -s /usr/sbin/nologin warden-cipher
USER 10005:10001
HEALTHCHECK --interval=10s --timeout=6s --start-period=120s --retries=3 CMD ["node", "healthcheck.mjs"]
CMD ["node", "start.mjs"]
