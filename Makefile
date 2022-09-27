all: build-ebpf build-assets build

build-ebpf:
	mkdir -p ebpf/bin
	clang -g -O2 -c -I./ebpf/headers -target bpf -D__TARGET_ARCH_x86 -o ./ebpf/bin/tc_dns.o ./ebpf/tc_dns.c

build-assets:
	go run github.com/shuLhan/go-bindata/cmd/go-bindata -pkg assets -o "./assets/probe.go" $(wildcard ./ebpf/bin/*.o)

build:
	go build -o edns

run:
	./edns

clean:
	rm -f ebpf/bin/*.o edns