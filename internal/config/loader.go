package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// LoadConfig reads and parses a config.yaml file at the given path.
// Unknown fields cause an error (strict mode).
func LoadConfig(path string) (*VectisConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config.yaml: %w", err)
	}
	defer f.Close()

	var cfg VectisConfig
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to load config.yaml: %w", err)
	}
	return &cfg, nil
}

// LoadSecrets reads and parses a secrets.yaml file at the given path.
// Unknown fields cause an error (strict mode).
func LoadSecrets(path string) (*VectisSecrets, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load secrets.yaml: %w", err)
	}
	defer f.Close()

	var secrets VectisSecrets
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&secrets); err != nil {
		return nil, fmt.Errorf("failed to load secrets.yaml: %w", err)
	}
	return &secrets, nil
}

// LoadAll is a convenience function that loads both config.yaml and
// secrets.yaml from the given directory.
func LoadAll(configDir string) (*VectisConfig, *VectisSecrets, error) {
	cfg, err := LoadConfig(filepath.Join(configDir, "config.yaml"))
	if err != nil {
		return nil, nil, err
	}

	secrets, err := LoadSecrets(filepath.Join(configDir, "secrets.yaml"))
	if err != nil {
		return nil, nil, err
	}

	return cfg, secrets, nil
}
