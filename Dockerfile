# Build the Next.js application
FROM node:22-bookworm-slim AS builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# Run the compiled application
FROM node:22-bookworm-slim AS runner

WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/src ./src
COPY --from=builder /app/data ./data
COPY --from=builder /app/next.config.ts ./next.config.ts
COPY --from=builder /app/tsconfig.json ./tsconfig.json
COPY --from=builder /app/next-env.d.ts ./next-env.d.ts

EXPOSE 3100

CMD ["sh", "-c", "node -e \"const fs=require('fs'); const p='data/tidecloak.json'; const c=JSON.parse(fs.readFileSync(p, 'utf8')); c['auth-server-url']='http://tidecloak:8080/'; fs.writeFileSync(p, JSON.stringify(c));\" && npm run start"]
