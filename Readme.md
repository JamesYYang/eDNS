# eDNS - ebpf TC DNS

## About
eDNS is an experimental DNS component written in BPF for high throughput, low latency DNS responses.  
It uses TC ingress / egress to process packets early in the Linux networking path.  
A user space application is provided to add DNS records to a BPF map which is read from K8S informer or load from static file.

## Use Case and Concept
In Kubernetes, pods communicate by service name. So a DNS query is needed before every request. The CoreDNS deployed by default in the Kubernetes cluster may experience problems such as high DNS resolution delay, resolution timeout, and resolution failure in scenarios with high DNS QPS.  
eDNS can be used to solve this problem. It watch any servcie change in kubernetes then add service name and IP to ebpf map. And it also can load domain config from static file.  
eDNS use ebpf tc ingress / egress hook, and response the DNS request which the query domain is kubernetes serivce name.

## Features & limitations
- Currently supports A records
- Only supports plain DNS over UDP (port 53)
- Basic EDNS implementation
- Only responds to single queries for now
- No recursive lookups
- Can't use in cilium network.

## How to Choose tc Hook
In Kubernetes, it is better use tc ingress hook to veth interface in host.  
config.yaml  
```yaml
ExtBTF: 
EnableK8S: true
IsInK8S: true
Ifname: veth5b0d81b
NetworkDirection: Ingress
```

In docker native, it is better use tc egress hook to physical network interface in host.  
config.yaml
```yaml
ExtBTF: 
EnableK8S: true
IsInK8S: true
Ifname: 
NetworkDirection: Egress
```

## How to Run

You can clone this repository and build binary.  
Please install package before building.  
```bash
sudo apt-get update
sudo apt-get install golang-go
sudo apt-get install make clang llvm
```
Then use make to build binary file.
```bash
make
./edns
```

Also you can run from docker image.
```bash
docker run -d \
  --name=edns \
  --net=host \
  --privileged \
  -v /sys/kernel/debug:/sys/kernel/debug \
  jamesyyang/edns:0.0.2
```

## Reference

- https://github.com/lizrice/ebpf-networking
- https://github.com/ehids/ebpfmanager