FROM node:20-slim

WORKDIR /app

# better-sqlite3 is a native module; install build tools as a fallback in
# case there's no prebuilt binary for this platform.
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

COPY package.json ./
RUN npm install --omit=dev

COPY . .
RUN node seed.js

# The app has no reason to run as root: if the deliberate SQL injection is ever turned into more, it stays in a
# container user that owns nothing but /app.
RUN chown -R node:node /app
USER node

EXPOSE 3000
CMD ["node", "server.js"]
