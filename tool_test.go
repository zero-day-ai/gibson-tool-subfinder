package subfinder

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToolImpl_Name(t *testing.T) {
	tool := NewTool()
	assert.Equal(t, "subfinder", tool.Name())
}

func TestToolImpl_Version(t *testing.T) {
	tool := NewTool()
	assert.Equal(t, "1.0.0", tool.Version())
}

func TestToolImpl_InputMessageType(t *testing.T) {
	tool := NewTool()
	assert.Equal(t, "gibson.tools.subfinder.SubfinderRequest", tool.InputMessageType())
}

func TestToolImpl_OutputMessageType(t *testing.T) {
	tool := NewTool()
	assert.Equal(t, "gibson.tools.subfinder.SubfinderResponse", tool.OutputMessageType())
}

func TestToolImpl_Tags(t *testing.T) {
	tool := NewTool()
	tags := tool.Tags()
	assert.Contains(t, tags, "discovery")
	assert.Contains(t, tags, "subdomain")
	assert.Contains(t, tags, "passive")
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
	}{
		{
			name:    "valid domain",
			domain:  "example.com",
			wantErr: false,
		},
		{
			name:    "valid subdomain",
			domain:  "api.example.com",
			wantErr: false,
		},
		{
			name:    "empty domain",
			domain:  "",
			wantErr: true,
		},
		{
			name:    "domain with spaces",
			domain:  "example .com",
			wantErr: true,
		},
		{
			name:    "domain without dot",
			domain:  "localhost",
			wantErr: true,
		},
		{
			name:    "domain too long",
			domain:  "a" + string(make([]byte, 260)) + ".com",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateDomain(tt.domain)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseOutput(t *testing.T) {
	tests := []struct {
		name     string
		output   []byte
		expected []string
	}{
		{
			name:     "empty output",
			output:   []byte(""),
			expected: []string{},
		},
		{
			name: "single JSON line",
			output: []byte(`{"host":"api.example.com","input":"example.com","source":["certspotter"]}
`),
			expected: []string{"api.example.com"},
		},
		{
			name: "multiple JSON lines",
			output: []byte(`{"host":"api.example.com","input":"example.com","source":["certspotter"]}
{"host":"www.example.com","input":"example.com","source":["certspotter"]}
{"host":"mail.example.com","input":"example.com","source":["certspotter"]}
`),
			expected: []string{"api.example.com", "www.example.com", "mail.example.com"},
		},
		{
			name: "duplicate subdomains",
			output: []byte(`{"host":"api.example.com","input":"example.com","source":["certspotter"]}
{"host":"api.example.com","input":"example.com","source":["crtsh"]}
`),
			expected: []string{"api.example.com"},
		},
		{
			name: "plain text fallback",
			output: []byte(`api.example.com
www.example.com
mail.example.com
`),
			expected: []string{"api.example.com", "www.example.com", "mail.example.com"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subdomains, err := parseOutput(tt.output)
			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.expected, subdomains)
		})
	}
}

