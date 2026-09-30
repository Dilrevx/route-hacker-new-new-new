FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
COPY openapi2/ openapi2/
COPY openapi2conv/ openapi2conv/
COPY openapi3/ openapi3/
COPY openapi3conv/ openapi3conv/
COPY openapi3filter/ openapi3filter/
COPY openapi3gen/ openapi3gen/
COPY routers/ routers/

ENV GOPROXY=https://goproxy.cn,direct

RUN go mod download

COPY app/ app/
RUN cd app && go mod tidy && CGO_ENABLED=0 go build -o /app-server .

FROM scratch

COPY --from=builder /app-server /app-server
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY app/openapi.yaml /openapi.yaml

EXPOSE 8080
ENV OPENAPI_SPEC=/openapi.yaml
ENV PORT=8080

ENTRYPOINT ["/app-server"]
