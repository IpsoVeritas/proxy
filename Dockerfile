ARG BUILDER=golang:1.16
FROM ${BUILDER} AS build

ARG GITHUB_USER
ARG GITHUB_PASSWORD
RUN echo "machine github.com login ${GITHUB_USER} password ${GITHUB_PASSWORD}" > ~/.netrc
ENV GOPRIVATE=github.com/IpsoVeritas

WORKDIR /code/proxy
ADD go.mod .
ADD go.sum .
RUN go mod download

ADD . .

ARG VERSION=0.0.0-snapshot
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X github.com/IpsoVeritas/proxy/pkg/version.Version=$VERSION" -o /proxy-server ./cmd/proxy-server

FROM alpine:3.11

COPY --from=build /proxy-server /proxy-server

CMD [ "/proxy-server" ]