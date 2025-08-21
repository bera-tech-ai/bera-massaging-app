FROM node:18-alpine

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY backend/package*.json ./backend/

# Install root dependencies
RUN npm install

# Install backend dependencies
WORKDIR /app/backend
RUN npm install

# Install frontend dependencies (if you had a frontend package.json)
WORKDIR /app
COPY frontend/ ./frontend/

# For a real frontend build process, you would add:
# WORKDIR /app/frontend
# RUN npm install && npm run build

# Copy source code
COPY . .

# Expose port
EXPOSE 3000

# Set environment to production
ENV NODE_ENV=production

# Start the application
CMD ["npm", "start"]
