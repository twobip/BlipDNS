package controller

import "gopkg.in/yaml.v3"

// yamlUnmarshal parses YAML into v (yaml.v3 wrapper so callers don't import
// the dependency directly).
func yamlUnmarshal(b []byte, v interface{}) error {
	return yaml.Unmarshal(b, v)
}
