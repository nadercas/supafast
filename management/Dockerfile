FROM node:20-alpine

# Install docker CLI (for compose pull/up) and restic (for backup management)
RUN apk add --no-cache docker-cli docker-cli-compose restic bash

WORKDIR /app
COPY package.json ./
RUN npm install --production 2>/dev/null; exit 0
COPY server.js ./
COPY public ./public
EXPOSE 3001
USER node
CMD ["node", "server.js"]
