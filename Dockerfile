FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/proof/package.json packages/proof/package.json
COPY packages/server/package.json packages/server/package.json
COPY packages/client/package.json packages/client/package.json
RUN npm ci
COPY . .
RUN npm run build -w @agenticage/proof
EXPOSE 8787
CMD ["npm", "run", "start", "-w", "@agenticage/server"]
