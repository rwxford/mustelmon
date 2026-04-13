FROM node:22-alpine

WORKDIR /app

# Copy application files (no node_modules needed — zero dependencies)
COPY package.json server.js ./
COPY public/ ./public/

EXPOSE 3000

# Run as non-root by default; override with --user root if /proc access is restricted
USER node

CMD ["node", "server.js"]
