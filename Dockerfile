FROM node:24-bookworm AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

FROM node:24-bookworm-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=dependencies --chown=node:node /app/node_modules ./node_modules
COPY --chown=node:node package.json server.js index.html ./
COPY --chown=node:node scripts ./scripts
COPY --chown=node:node styles ./styles
COPY --chown=node:node assets ./assets
RUN npm run check
RUN mkdir -p /app/data /app/backups && chown -R node:node /app/data /app/backups
USER node
EXPOSE 8000
CMD ["node", "server.js"]
