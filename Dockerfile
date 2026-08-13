FROM node:22-alpine

RUN apk add --no-cache \
      chromium \
      nss \
      freetype \
      harfbuzz \
      ca-certificates \
      ttf-freefont \
      font-noto-cjk \
      dumb-init

ENV PUPPETEER_SKIP_DOWNLOAD=true \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=true \
    CHROMIUM_PATH=/usr/bin/chromium-browser

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY . .

ENV FLARESOLVERR_URL=http://flaresolverr:8191/v1 \
    PORT=9191

EXPOSE 9191

ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["node", "server.mjs"]
