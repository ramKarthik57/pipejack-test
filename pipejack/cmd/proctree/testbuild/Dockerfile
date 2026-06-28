FROM node:18-alpine
RUN apk add --no-cache bash
WORKDIR /app
COPY package.json index.js ./
COPY proctree /usr/local/bin/proctree
COPY policy.yaml /app/.pipejack/policy.yaml
# Simulate a build: npm install, then run the monitor
CMD npm install && proctree
