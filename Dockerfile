FROM golang:1.27.1-alpine3.24 AS build
RUN apk add --no-cache build-base libpcap-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags '-extldflags "-static"' \
      -o /out/sunet-xdpd

FROM scratch
COPY --from=build /out/sunet-xdpd /
