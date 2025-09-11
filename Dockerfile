# STAGE 1 — Build
FROM golang:1.24.1-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o main ./cmd

# STAGE 2 — Run
FROM alpine:3.20

WORKDIR /app
COPY --from=builder /app/main .

CMD ["./main"]
