package modules

import (
	"log"
	"net"
	"strconv"
	"strings"
)

var localIP = ""
var localIFace = ""

func GetLocalIP() (string, string) {
	if localIP != "" {
		return localIP, localIFace
	}
	addrs, iface, err := getLocalNetAddrs()
	if err != nil {
		log.Printf("get local ip addr error: %s", err)
	}
	localIFace = iface
	localIP = addrs
	return localIP, iface
}

func getLocalNetAddrs() (string, string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // 忽略禁用的网卡
		}

		if iface.Flags&net.FlagLoopback != 0 {
			continue // 忽略loopback回路接口
		}

		// 忽略 docker网桥与虚拟网络
		if strings.HasPrefix(iface.Name, "docker") ||
			strings.HasPrefix(iface.Name, "veth") ||
			strings.HasPrefix(iface.Name, "br-") ||
			strings.HasPrefix(iface.Name, "w-") ||
			strings.HasPrefix(iface.Name, "vEthernet") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			return "", "", err
		}

		for _, addr := range addrs {

			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			if ip == nil || ip.IsLoopback() {
				continue
			}

			ip = ip.To4()
			if ip == nil {
				continue // 不是ipv4地址，放弃
			}

			ipStr := ip.String()
			if isIntranet(ipStr) {
				return ipStr, iface.Name, nil
			}
		}
	}
	return "", "", nil
}

func isIntranet(ipStr string) bool {

	if strings.HasPrefix(ipStr, "10.") || strings.HasPrefix(ipStr, "192.168.") {
		return true
	}

	if strings.HasPrefix(ipStr, "172.") {
		// 172.16.0.0-172.31.255.255
		arr := strings.Split(ipStr, ".")
		if len(arr) != 4 {
			return false
		}

		second, err := strconv.ParseInt(arr[1], 10, 64)
		if err != nil {
			return false
		}

		if second >= 16 && second <= 31 {
			return true
		}
	}
	return false
}
