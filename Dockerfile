FROM node:16.3.0-alpine As development

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install --only=development

COPY . .

RUN npm run build

RUN npx prisma generate

CMD ["npx", "prisma", "db", "push"]
