FROM --platform=${BUILDPLATFORM} golang:1.26-alpine AS build

ARG BUILDPLATFORM
ARG TARGETPLATFORM
ARG TARGETOS
ARG TARGETARCH

WORKDIR /go/src/app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build  -ldflags="-w -s" -o did-helper .

FROM alpine:3.23

ENV KEY_TYPE_TO_GENERATE="EC"


ENV COUNTRY="DE"
ENV STATE="Saxony"
ENV LOCALITY="Dresden"
ENV ORGANIZATION="M&P Operations Inc."
ENV COMMON_NAME="www.mp-operations.org"
ENV STORE_PASS="myPassword"
ENV KEY_ALIAS="myAlias"
ENV KEY_TYPE="P-256"
ENV OUTPUT_FORMAT="json"
ENV DID_TYPE="key"
ENV OUTPUT_FILE="/cert/did.json"

RUN apk add --no-cache openssl wget bash

RUN mkdir /cert
RUN mkdir /did-helper
RUN chmod a+rw /cert
RUN chmod a+rw /did-helper

WORKDIR /did-helper

COPY --from=build /go/src/app/did-helper ./did-helper
COPY --from=build /go/src/app/docker/entrypoint.sh /temp/entrypoint.sh

RUN chmod a+x /temp/entrypoint.sh
ENTRYPOINT ["/temp/entrypoint.sh"]
