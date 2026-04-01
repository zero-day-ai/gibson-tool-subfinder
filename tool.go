package subfinder

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/exec"
	"github.com/zero-day-ai/sdk/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/toolerr"
	"github.com/zero-day-ai/sdk/types"
	"github.com/zero-day-ai/gibson-tool-subfinder/gen"
	"google.golang.org/protobuf/proto"
)

const (
	ToolName        = "subfinder"
	ToolVersion     = "1.0.0"
	ToolDescription = `Subdomain enumeration tool using passive sources. Discovers subdomains for a target domain.

USAGE:
  Provide a domain to enumerate subdomains using multiple passive sources including:
  - Certificate Transparency logs
  - DNS datasets
  - Search engines
  - Other passive sources

EXAMPLES:
  Domain: "example.com"
  Domain: "api.example.com"`
	BinaryName = "subfinder"
)

// ToolImpl implements the subfinder tool
type ToolImpl struct{}

// NewTool creates a new subfinder tool instance
func NewTool() tool.Tool {
	return &ToolImpl{}
}

// Name returns the tool name
func (t *ToolImpl) Name() string {
	return ToolName
}

// Version returns the tool version
func (t *ToolImpl) Version() string {
	return ToolVersion
}

// Description returns the tool description
func (t *ToolImpl) Description() string {
	return ToolDescription
}

// Tags returns the tool tags
func (t *ToolImpl) Tags() []string {
	return []string{
		"discovery",
		"subdomain",
		"passive",
		"T1590.001", // Gather Victim Network Information: Domain Properties
		"T1592.001", // Gather Victim Host Information: Hardware
	}
}

// InputMessageType returns the proto message type for input
func (t *ToolImpl) InputMessageType() string {
	return "gibson.tools.subfinder.SubfinderRequest"
}

// OutputMessageType returns the proto message type for output
func (t *ToolImpl) OutputMessageType() string {
	return "gibson.tools.subfinder.SubfinderResponse"
}

// InputProto returns a prototype instance of the input message.
// Implements the serve.SchemaProvider interface for reliable schema extraction.
func (t *ToolImpl) InputProto() proto.Message {
	return &gen.SubfinderRequest{}
}

// OutputProto returns a prototype instance of the output message.
// Implements the serve.SchemaProvider interface for reliable schema extraction.
func (t *ToolImpl) OutputProto() proto.Message {
	return &gen.SubfinderResponse{}
}

// ExecuteProto runs the subfinder tool with proto message input
func (t *ToolImpl) ExecuteProto(ctx context.Context, input proto.Message) (proto.Message, error) {
	startTime := time.Now()

	// Type assert input to SubfinderRequest
	req, ok := input.(*gen.SubfinderRequest)
	if !ok {
		return nil, fmt.Errorf("invalid input type: expected *gen.SubfinderRequest, got %T", input)
	}

	// Validate required fields
	if req.Domain == "" {
		return nil, toolerr.New(ToolName, "validate", toolerr.ErrCodeInvalidInput, "domain is required").
			WithClass(toolerr.ErrorClassSemantic)
	}

	// Validate domain format (basic validation)
	if err := validateDomain(req.Domain); err != nil {
		return nil, toolerr.New(ToolName, "validate", toolerr.ErrCodeInvalidInput, err.Error()).
			WithClass(toolerr.ErrorClassSemantic)
	}

	// Build command arguments: -d domain -silent -json
	args := []string{"-d", req.Domain, "-json"}

	// Add silent flag if requested (silent is the default for JSON mode)
	if req.Silent {
		args = append(args, "-silent")
	}

	// Determine timeout
	timeout := 5 * time.Minute // Default timeout
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}

	// Execute subfinder command
	result, err := exec.Run(ctx, exec.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		// Classify execution errors based on underlying cause
		errClass := classifyExecutionError(err)
		return nil, toolerr.New(ToolName, "execute", toolerr.ErrCodeExecutionFailed, err.Error()).
			WithCause(err).
			WithClass(errClass)
	}

	// Parse subfinder JSON output to proto types
	subdomains, err := parseOutput(result.Stdout)
	if err != nil {
		return nil, toolerr.New(ToolName, "parse", toolerr.ErrCodeParseError, err.Error()).
			WithCause(err).
			WithClass(toolerr.ErrorClassSemantic)
	}

	// Build DiscoveryResult for graph population
	discoveryResult := buildDiscoveryResult(req.Domain, subdomains)

	// Build response
	scanDuration := time.Since(startTime).Seconds()
	response := &gen.SubfinderResponse{
		Subdomains: subdomains,
		TotalFound: int32(len(subdomains)),
		Discovery:  discoveryResult,
	}

	// Log completion
	_ = scanDuration // Use scan duration if needed for logging

	return response, nil
}

// Health checks if the subfinder binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// SubfinderOutput represents a single line of JSON output from subfinder
type SubfinderOutput struct {
	Host   string   `json:"host"`
	Input  string   `json:"input"`
	Source []string `json:"source"`
}

// parseOutput parses the JSON output from subfinder and returns subdomain list
func parseOutput(data []byte) ([]string, error) {
	var subdomains []string
	seenSubdomains := make(map[string]bool)

	// subfinder outputs one JSON object per line
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		var output SubfinderOutput
		if err := json.Unmarshal([]byte(line), &output); err != nil {
			// If JSON parsing fails, try to use the line as a plain subdomain
			subdomain := strings.TrimSpace(line)
			if subdomain != "" && !seenSubdomains[subdomain] {
				subdomains = append(subdomains, subdomain)
				seenSubdomains[subdomain] = true
			}
			continue
		}

		// Add the discovered subdomain
		if output.Host != "" && !seenSubdomains[output.Host] {
			subdomains = append(subdomains, output.Host)
			seenSubdomains[output.Host] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan subfinder output: %w", err)
	}

	return subdomains, nil
}

// buildDiscoveryResult builds the DiscoveryResult for graph population
func buildDiscoveryResult(domain string, subdomains []string) *graphragpb.DiscoveryResult {
	result := &graphragpb.DiscoveryResult{}

	// Create a domain node for the root domain
	result.Domains = append(result.Domains, &graphragpb.Domain{
		Name: domain,
	})

	// Create subdomain nodes
	for _, subdomain := range subdomains {
		// Skip if subdomain is the same as the root domain
		if subdomain == domain {
			continue
		}

		result.Domains = append(result.Domains, &graphragpb.Domain{
			Name: subdomain,
		})
	}

	return result
}

// validateDomain performs basic domain validation
func validateDomain(domain string) error {
	domain = strings.TrimSpace(domain)

	if len(domain) == 0 {
		return fmt.Errorf("domain cannot be empty")
	}

	if len(domain) > 253 {
		return fmt.Errorf("domain name too long (max 253 characters)")
	}

	// Check for invalid characters
	if strings.Contains(domain, " ") {
		return fmt.Errorf("domain cannot contain spaces")
	}

	// Very basic validation - should contain at least one dot for a valid domain
	if !strings.Contains(domain, ".") {
		return fmt.Errorf("domain must contain at least one dot (e.g., example.com)")
	}

	return nil
}

// classifyExecutionError determines the error class based on the underlying error
func classifyExecutionError(err error) toolerr.ErrorClass {
	if err == nil {
		return toolerr.ErrorClassTransient
	}

	errMsg := err.Error()

	// Check for binary not found errors
	if strings.Contains(errMsg, "not found") || strings.Contains(errMsg, "executable file not found") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for timeout errors
	if strings.Contains(errMsg, "timed out") || strings.Contains(errMsg, "timeout") ||
		strings.Contains(errMsg, "deadline exceeded") {
		return toolerr.ErrorClassTransient
	}

	// Check for permission errors
	if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "access denied") {
		return toolerr.ErrorClassInfrastructure
	}

	// Check for network errors
	if strings.Contains(errMsg, "network") || strings.Contains(errMsg, "connection") ||
		strings.Contains(errMsg, "host unreachable") || strings.Contains(errMsg, "no route to host") {
		return toolerr.ErrorClassTransient
	}

	// Check for cancellation
	if strings.Contains(errMsg, "cancelled") || strings.Contains(errMsg, "canceled") {
		return toolerr.ErrorClassTransient
	}

	// Default to transient for unknown execution errors
	return toolerr.ErrorClassTransient
}
