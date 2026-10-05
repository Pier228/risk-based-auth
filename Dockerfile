FROM node:20-slim

WORKDIR /app

COPY package*.json /app

RUN npm install

RUN apt-get update -y && apt-get install -y openssl

COPY . .

RUN npx prisma generate

RUN npm run build

CMD ["npm", "run", "start:prod"]