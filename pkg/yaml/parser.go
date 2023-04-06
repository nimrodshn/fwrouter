package yaml

import (
	"fwrouter/pkg/api"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type Parser interface {
	Parse(file string) (*api.Config, error)
}

type YamlParser struct{}

func NewParser() Parser {
	return &YamlParser{}
}

func (p *YamlParser) Parse(file string) (*api.Config, error) {
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var config api.Config
	if err = yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
