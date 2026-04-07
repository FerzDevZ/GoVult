package template

type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
	Exploit  *Exploit  `yaml:"exploit"`
}

type Info struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

type Request struct {
	Method    string      `yaml:"method"`
	Path      []string    `yaml:"path"`
	Headers   map[string]string `yaml:"headers"`
	Body      string      `yaml:"body"`
	Matchers  []Matcher   `yaml:"matchers"`
	Extractors []Extractor `yaml:"extractors"`
}

type Matcher struct {
	Type      string   `yaml:"type"`      // word, status, size, regex, css, json
	Condition string   `yaml:"condition"` // and, or
	Part      string   `yaml:"part"`      // body, header, status
	Words     []string `yaml:"words"`
	Status    []int    `yaml:"status"`
	Regex     []string `yaml:"regex"`
	Size      []int    `yaml:"size"`
	CSS       []string `yaml:"css"`
	JSON      []string `yaml:"json"`
	Duration  int      `yaml:"duration"` // in seconds, matches if >= Duration
}

type Extractor struct {
	Type  string `yaml:"type"` // regex, json, header
	Regex []string `yaml:"regex"`
	JSON  []string `yaml:"json"`
	Name  string `yaml:"name"` // Variable name for chaining
}

type Exploit struct {
	Steps []ExploitStep `yaml:"steps"`
}

type ExploitStep struct {
	Method   string            `yaml:"method"`
	Path     string            `yaml:"path"`
	Headers  map[string]string `yaml:"headers"`
	Body     string            `yaml:"body"`
	Matchers []Matcher         `yaml:"matchers"`
}
