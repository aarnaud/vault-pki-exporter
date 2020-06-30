FROM golang:alpine AS builderimage
WORKDIR /go/src/vault-pki-exporter
COPY . .
RUN go build -o vault-pki-exporter cmd/main.go


###################################################################

FROM alpine
COPY --from=builderimage /go/src/vault-pki-exporter/vault-pki-exporter /app/
WORKDIR /app
EXPOSE 9333
CMD ./vault-pki-exporter