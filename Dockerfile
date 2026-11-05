# syntax=docker/dockerfile:1
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/bin/bima ./cmd/bima
# test-only tools (mocks, load generator, fake GeoIP DBs for documentation IP ranges)
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/test/mockapp ./test/e2e/mockapp \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/test/mocknotify ./test/e2e/mocknotify \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/test/loadgen ./test/e2e/loadgen \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/test/scenariorun ./test/e2e/scenariorun \
 && go run ./test/e2e/genmmdb /out/geo

# Production image: agent only.
FROM alpine:3.20 AS runtime
RUN adduser -D -H -u 10001 bima && mkdir -p /var/lib/bima && chown bima /var/lib/bima
COPY --from=build /out/bin/bima /usr/local/bin/bima
USER bima
EXPOSE 12345 9101
CMD ["/usr/local/bin/bima", "-config", "/etc/bima/config.yaml"]

# E2E image: agent + mocks + test GeoIP data.
FROM runtime AS e2e
COPY --from=build /out/test/ /usr/local/bin/
COPY --from=build /out/geo/ /usr/share/bima/geo/

# Skill e2e: a "fresh host" with HAProxy and the bima binary, set up via the skill workflow.
FROM haproxy:3.0-alpine AS skilltest
USER root
RUN apk add --no-cache bash curl jq
COPY --from=build /out/bin/bima /usr/local/bin/bima
COPY --from=build /out/test/mockapp /out/test/mocknotify /usr/local/bin/

FROM runtime
