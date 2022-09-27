FROM golang:1.18-alpine

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

RUN apk update \
  && apk upgrade --no-cache \
  && apk add --no-cache tzdata make clang llvm bash dumb-init

WORKDIR /dist

COPY ./assets /dist/assets

COPY ./config /dist/config

COPY ./ebpf /dist/ebpf

COPY ./modules /dist/modules

COPY ./kernel /dist/kernel

COPY ./go.mod /dist/

COPY ./go.sum /dist/

COPY ./eDNS.go /dist/

COPY ./Makefile /dist/

RUN go env -w GOPROXY=https://goproxy.cn,direct

RUN make

ENTRYPOINT ["dumb-init", "--"]

CMD ["./edns"]