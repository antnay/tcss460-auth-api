FROM node:23-alpine

WORKDIR /app

COPY package.json package-lock.json ./

RUN npm ci

RUN npm install -g nodemon

COPY . .

RUN npm run build

CMD ["/bin/sh", "-c", "if [ \"$NODE_ENV\" = \"production\" ]; then echo 'Starting production server' && exec npm run local; else echo 'Starting development server with hot reload' && exec npm run dev; fi"]
