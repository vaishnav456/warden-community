FROM golang:1.27.1-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN mkdir /dist && \
    CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o /dist/warden-home-node-windows-amd64.exe . && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' -o /dist/warden-home-node-linux-amd64 . && \
    sed -n 's/^const homeNodeVersion = "\([^"]*\)"/\1/p' managed_update.go > /dist/version.txt

FROM alpine:3.20
COPY --from=build /dist/ /artifacts/
USER 10001:10001
ENTRYPOINT ["/bin/sh", "-ec", "cp /artifacts/warden-home-node-windows-amd64.exe /artifacts/warden-home-node-linux-amd64 /artifacts/version.txt /output/"]
