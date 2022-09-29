# eDNS - ebpf TC DNS

## About
eDNS is an experimental DNS component written in BPF for high throughput, low latency DNS responses.  
It uses TC egress to process packets early in the Linux networking path.  
A user space application is provided to add DNS records to a BPF map which is read from K8S informer.

## Use Case and Concept
In Kubernetes, pods communicate by service name. So a DNS query is needed before every request. The CoreDNS deployed by default in the Kubernetes cluster may experience problems such as high DNS resolution delay, resolution timeout, and resolution failure in scenarios with high DNS QPS.  
eDNS can be used to solve this problem. It watch any servcie change in kubernetes then add service name and IP to ebpf map.  
eDNS use ebpf tc egress hook, and response the DNS request which the query domain is kubernetes serivce name.
