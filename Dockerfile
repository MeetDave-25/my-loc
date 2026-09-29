FROM node:22-alpine

WORKDIR /app

# Install production deps first for better layer caching.
COPY package*.json ./
RUN npm ci --omit=dev

# App source.
COPY . .

ENV NODE_ENV=production
EXPOSE 3000

# Drop root.
USER node

CMD ["node", "server.js"]
