FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies first (cached layer — only re-runs if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Create directories if not bundled (safety)
RUN mkdir -p static/css templates

# Expose the port uvicorn will listen on
EXPOSE 8000

# Start the server
# Use --host 0.0.0.0 so it's reachable from outside the container
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
