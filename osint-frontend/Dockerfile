# Build stage
FROM node:18-alpine as build

# Set working directory
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy project files
COPY . .

# Build the app
RUN npm run build

# Production stage
FROM nginx:alpine

# Install bash for the entrypoint script
RUN apk add --no-cache bash

# Copy built files from build stage
COPY --from=build /app/build /usr/share/nginx/html

# Copy nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Create an entrypoint script with proper formatting
RUN echo '#!/bin/bash' > /docker-entrypoint.sh && \
	echo 'find /usr/share/nginx/html -name "*.js" -exec sed -i "s|http://backend:5000/api/v1/main|${REACT_APP_BACKEND_URL}|g" {} \;' >> /docker-entrypoint.sh && \
	echo 'nginx -g "daemon off;"' >> /docker-entrypoint.sh && \
	chmod +x /docker-entrypoint.sh

# Expose port
EXPOSE 80

# Use the entrypoint script
ENTRYPOINT ["/docker-entrypoint.sh"]