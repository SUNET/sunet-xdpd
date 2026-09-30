FROM golang:1.27.1-alpine3.24 AS build
RUN apk add --no-cache build-base libpcap-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=1 go build -trimpath \
      -ldflags "-X main.version=${VERSION} -extldflags='-static'" \
      -o /out/sunet-xdpd

# Verify the file we built is statically linked by checking there is no INTERP
# header in it.
RUN set -o pipefail && readelf -lW /out/sunet-xdpd | awk '$1 == "INTERP" { exit 1 }'

FROM scratch
COPY --from=build /out/sunet-xdpd /
