FROM golang:1.21

WORKDIR /app

COPY . .

# Running as root - CWE-250
RUN go build -o /app/server ./cmd/api

# Exposing debug port
EXPOSE 8080
EXPOSE 6060

# No health check, no non-root user
CMD ["/app/server"]
