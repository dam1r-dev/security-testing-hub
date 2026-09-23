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

EXPOSE 3000
CMD ["node", "server.js"]
