FROM python:3.13-alpine

# Configurable Environment Variables
ENV PORT=5514
ENV LOG_LEVEL=informational
ENV TZ=UTC
ENV LOKI_URL=http://loki:3100

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY ./container /app

# Create a directory for the database
RUN mkdir /app/database

# Install any needed packages specified in requirements.txt
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Expose Syslog UDP port
EXPOSE ${PORT}/udp

# Add a health check to verify if the UDP port is listening
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD nc -z -u 127.0.0.1 ${PORT} || exit 1

# Run main.py when the container launches, adding unbuffered mode and src to sys.path
CMD ["python", "-u", "main.py"]