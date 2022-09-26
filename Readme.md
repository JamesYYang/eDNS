# eDNS - ebpf TC DNS

## About
eDNS is an experimental DNS component written in BPF for high throughput, low latency DNS responses.  
It uses TC egress to process packets early in the Linux networking path.  
A user space application is provided to add DNS records to a BPF map which is read from K8S informer.