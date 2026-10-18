FROM node:24-alpine
WORKDIR /app
COPY package.json server.mjs ./
ENV NODE_ENV=production DATA_DIR=/data PORT=8787
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME /data
EXPOSE 8787
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8787/api/health || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "server.mjs"]
