FROM golang:1.26-alpine AS build
WORKDIR /src
COPY main.go .
RUN go mod init gotls >/dev/null 2>&1 && CGO_ENABLED=0 go build -o /gotls . 
FROM alpine:3.22
COPY --from=build /gotls /gotls
ENTRYPOINT ["/gotls"]
