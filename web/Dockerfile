FROM node:20-alpine
WORKDIR /app
COPY package.json /app/package.json
RUN npm install --no-audit --no-fund
COPY index.html /app/index.html
COPY vite.config.js /app/vite.config.js
COPY src /app/src
EXPOSE 5173
CMD ["npm", "run", "dev"]
