package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type (
	Configuration struct {
		ExtBTF           string `yaml:"ExtBTF"`
		EnableK8S        bool   `yaml:"EnableK8S"`
		IsInK8S          bool   `yaml:"IsInK8S"`
		Ifname           string `yaml:"Ifname"`
		NetworkDirection string `yaml:"NetworkDirection"`
	}
)

func NewConfig() (*Configuration, error) {
	fname := "config/config.yaml"

	configuration := &Configuration{}
	data, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	if err = yaml.Unmarshal(data, configuration); err != nil {
		return nil, err
	}

	return configuration, nil
}
