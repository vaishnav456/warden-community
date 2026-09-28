FROM golang:1.27.1-bookworm AS gosu-build
ENV CGO_ENABLED=0
RUN go install github.com/tianon/gosu@1.19

FROM postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea
COPY --from=gosu-build /go/bin/gosu /usr/local/bin/gosu
RUN gosu --version
