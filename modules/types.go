package modules

type DNSQuery struct {
	RecordType uint16
	Class      uint16
	Name       [256]byte
}

type DNSRecord struct {
	IP  uint32
	TTL uint32
}

type NetAddress struct {
	Host     string `yaml:"Host"`
	IP       string `yaml:"IP"`
	Svc      string `yaml:"Svc"`
	NS       string `yaml:"NS"`
	IsDelete bool   `yaml:"IsDelete"`
}

type Net_DNS_Event struct {
	TS         uint64
	RecordType uint16
	IsMatch    uint8
	Name       [256]byte
}
