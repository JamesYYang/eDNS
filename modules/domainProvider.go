package modules

import (
	"eDNS/config"
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type DomainProvider struct {
	kw            *K8SWatcher
	c             *config.Configuration
	ServiceChange chan NetAddress
}

type DomainConfig struct {
	DomainConfigs []DomainPair `yaml:"Domains"`
}

type DomainPair struct {
	Name string `yaml:"Name"`
	IP   string `yaml:"IP"`
}

func NewDomainProvider(c *config.Configuration) *DomainProvider {
	dp := &DomainProvider{
		ServiceChange: make(chan NetAddress, 50),
		c:             c,
	}

	return dp
}

func (dp *DomainProvider) LoadDomain() {
	dp.kw = NewWatcher(dp.c, dp.ServiceChange)
	dp.kw.Run()

	dp.LoadDomainConfig()
}

func (dp *DomainProvider) LoadDomainConfig() {
	fname := "config/domain.yaml"

	dc := &DomainConfig{}
	data, err := os.ReadFile(fname)
	if err != nil {
		log.Printf("load domain config failed: %v", err)
		return
	}
	if err = yaml.Unmarshal(data, dc); err != nil {
		log.Printf("load domain config failed: %v", err)
		return
	}

	for _, d := range dc.DomainConfigs {
		na := NetAddress{
			Host:     d.Name,
			IP:       d.IP,
			IsDelete: false,
		}
		dp.ServiceChange <- na
	}
}
