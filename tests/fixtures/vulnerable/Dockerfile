FROM node:latest
ARG NPM_TOKEN=npm_A1b2C3d4E5f6G7h8
RUN curl -fsSL https://get.example.com/install.sh | sh
ADD https://example.com/tool.tar.gz /opt/tool.tar.gz
ENV DB_PASSWORD=hunter2hunter2
COPY . /app
WORKDIR /app
RUN npm ci
EXPOSE 8080
CMD ["node", "server.js"]
