package template

type Template struct {
	ID       string    `yaml:"id"`
	Info     Info      `yaml:"info"`
	Requests []Request `yaml:"requests"`
}

type Info struct {
	Name        string `yaml:"name"`
	Author      string `yaml:"author"`
	Severity    string `yaml:"severity"`
	Description string `yaml:"description"`
}

type Request struct {
	Method   string    `yaml:"method"`
	Path     []string  `yaml:"path"`
	Matchers []Matcher `yaml:"matchers"`
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
}
