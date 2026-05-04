# Ultravisor Auth Beacon — long-running callback service.
# Connects OUT to an Ultravisor and serves the Authentication
# capability over the beacon WebSocket. No HTTP server of its own,
# so no EXPOSE / HEALTHCHECK — compose treats the container as
# healthy while the process is running.
#
# `npm install` (not `npm ci`) is intentional — package-lock.json is
# gitignored per the Quackage convention. See BUILDING-AND-PUBLISHING.md.

FROM node:20-slim
WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY source/ source/
COPY bin/ bin/

# Default ultravisor URL via env var; CLI flag still overrides at
# runtime. The bin script reads --ultravisor / --name / --join-secret
# for explicit configuration; mount /app/config and pass --config when
# you need a custom AuthProvider or persisted config.
ENV ULTRAVISOR_URL=http://ultravisor:54321 \
	BEACON_NAME=auth-beacon

RUN mkdir -p /app/config
VOLUME ["/app/config"]

CMD ["node", "bin/ultravisor-auth-beacon.js"]
