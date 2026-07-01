# syntax=docker/dockerfile:1
FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/relayd ./services/relay-reference/cmd/relayd

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/relayd /relayd
USER nonroot:nonroot
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD ["/relayd", "healthcheck"]
ENTRYPOINT ["/relayd"]

