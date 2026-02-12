package config

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

const CurrentVersion = 1

func Marshal(cfg *Config) ([]byte, error) {
	cfg.Version = CurrentVersion
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	return data, nil
}

func Unmarshal(data []byte) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if cfg.Version == 0 {
		cfg.Version = CurrentVersion
	}
	return &cfg, nil
}
