package internal

import (
	"io/ioutil"

	"gopkg.in/yaml.v3" // <-- добавьте эту строку
)

type Config struct {
	NodeID      uint32   `yaml:"node_id"`
	Listen      string   `yaml:"listen"`      // ":4433"
	GrpcListen  string   `yaml:"grpc_listen"` // ":50051"
	Transport   string   `yaml:"transport"`   // "udp" или "tls"
	CertFile    string   `yaml:"cert_file"`
	KeyFile     string   `yaml:"key_file"`
	Country     string   `yaml:"country"`
	City        string   `yaml:"city"`
	ExitAddr    string   `yaml:"exit_addr"`    // для Exit-узла
	MaxLoad     float64  `yaml:"max_load"`     // порог для балансировки
	InitialRole string   `yaml:"initial_role"` // entry, mid, exit, idle
	BootNodes   []string `yaml:"boot_nodes"`   // для клиента
	ExitCountry string   `yaml:"exit_country"` // для клиента
}

func LoadConfig(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	if cfg.MaxLoad == 0 {
		cfg.MaxLoad = 0.8
	}
	return &cfg, nil
}
