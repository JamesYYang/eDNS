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

/*
RFC 1035
4.1.2
QNAME           a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used.
*/

func replace_length_octets_with_dots(dns_name []byte) []byte {
	name_len := len(dns_name)
	new_dns_name := make([]byte, name_len-1)
	//Retrieve first label length octet
	label_length := dns_name[0]
	//Loop through dns name, starting at 1 (as position 0 contains length octet)
	for i := 1; i < name_len; i++ {
		//Break loop if zero
		if dns_name[i] == 0 {
			new_dns_name[i-1] = 0
			break
		} else if label_length == 0 {
			new_dns_name[i-1] = 46
			//Set label_length to current label length octet
			label_length = dns_name[i]
		} else {
			new_dns_name[i-1] = dns_name[i]
			label_length--
		}
	}
	return new_dns_name
}

func replace_dots_with_length_octets(dns_name []byte) []byte {
	name_len := len(dns_name)
	new_dns_name := make([]byte, name_len+1)
	cnt := 0
	for i := 0; i < name_len; i++ {
		//If dot character or end of string is detected
		if dns_name[i] == 46 || dns_name[i] == 0 {
			//Put length octet with value [cnt] at location [i-cnt]
			new_dns_name[i-cnt] = uint8(cnt)

			//Break loop if zero
			if dns_name[i] == 0 {
				cnt = i + 1
				break
			}

			//Reset counter
			cnt = -1
		}

		new_dns_name[i+1] = dns_name[i]

		//Count number of characters until the dot character
		cnt++
	}

	new_dns_name[cnt] = 0
	return new_dns_name
}
