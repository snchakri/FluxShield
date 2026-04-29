FROM node:20-alpine

WORKDIR /app

COPY package.json ./package.json
RUN npm install --omit=dev

COPY server.js ./server.js

ENV PORT=7000
ENV FILE_DB_PATH=/data

EXPOSE 7000

CMD ["npm", "start"]
