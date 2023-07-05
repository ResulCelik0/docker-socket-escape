FROM golang:latest as builder
WORKDIR /app
COPY . /app
RUN go build -o DockerSocketEscaper .


FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/DockerSocketEscaper /app
RUN chmod +x /app/DockerSocketEscaper
ENTRYPOINT ["DockerSocketEscaper" ]