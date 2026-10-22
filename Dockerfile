FROM node:24-alpine
WORKDIR /app
COPY . .
RUN npm install

EXPOSE 8888

CMD ["npm", "run", "start"]