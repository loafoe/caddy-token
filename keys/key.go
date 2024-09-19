package keys

type Key struct {
	Version      string   `json:"v"`
	Token        string   `json:"t"`
	Organization string   `json:"o"`
	Environment  string   `json:"e,omitempty"`
	Region       string   `json:"r"`
	Project      string   `json:"p,omitempty"`
	Scopes       []string `json:"s,omitempty"`
	Expires      int64    `json:"x,omitempty"`
}
