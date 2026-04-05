package subfinder

import (
	"context"
	"fmt"
	"strings"

	graphragpb "github.com/zero-day-ai/sdk/api/gen/gibson/graphrag/v1"
	"github.com/zero-day-ai/sdk/extraction"
	"github.com/zero-day-ai/gibson-tool-subfinder/gen"
	"google.golang.org/protobuf/proto"
)

// SubfinderExtractor extracts entities from subfinder scan results.
// It converts SubfinderResponse proto messages into DiscoveryResult containing:
//   - Domain entity for the root domain (inferred from the subdomain list)
//   - Subdomain entities for each discovered subdomain, linked to the root domain
type SubfinderExtractor struct{}

// NewSubfinderExtractor creates a new SubfinderExtractor instance.
func NewSubfinderExtractor() *SubfinderExtractor {
	return &SubfinderExtractor{}
}

func (e *SubfinderExtractor) ToolName() string { return "subfinder" }

func (e *SubfinderExtractor) CanExtract(msg proto.Message) bool {
	_, ok := msg.(*gen.SubfinderResponse)
	return ok
}

// Extract converts a SubfinderResponse into a DiscoveryResult.
//
// Because the extractor only receives the response (not the request), the root
// domain is inferred from the subdomain list: we take the longest common public
// suffix shared by all subdomains. For a typical subfinder run against
// "example.com", every result will be "*.example.com", so the last two labels
// of any subdomain reliably identify the root. For deeper roots (e.g. all
// results under "internal.example.com") the common-suffix logic handles it
// correctly by finding the longest shared suffix across all entries.
//
// If no subdomains are present, an empty DiscoveryResult is returned.
func (e *SubfinderExtractor) Extract(ctx context.Context, msg proto.Message) (*graphragpb.DiscoveryResult, error) {
	resp, ok := msg.(*gen.SubfinderResponse)
	if !ok {
		return nil, fmt.Errorf("expected *gen.SubfinderResponse, got %T", msg)
	}

	if len(resp.Subdomains) == 0 {
		return &graphragpb.DiscoveryResult{}, nil
	}

	rootDomain := inferRootDomain(resp.Subdomains)
	domainID := extraction.DomainID(rootDomain)

	discovery := &graphragpb.DiscoveryResult{}

	// Root domain node.
	discovery.Domains = append(discovery.Domains, &graphragpb.Domain{
		Id:   &domainID,
		Name: rootDomain,
	})

	// One Subdomain node per discovered entry that is not the root itself.
	for _, subdomain := range resp.Subdomains {
		if subdomain == rootDomain {
			continue
		}

		subID := extraction.SubdomainID(subdomain)
		// Name is the leftmost label(s), i.e. everything before the root suffix.
		name := strings.TrimSuffix(subdomain, "."+rootDomain)
		if name == subdomain {
			// Subdomain does not end with the inferred root; use the full string
			// as the name so no information is lost.
			name = subdomain
		}

		discovery.Subdomains = append(discovery.Subdomains, &graphragpb.Subdomain{
			Id:       &subID,
			DomainId: domainID,
			Name:     name,
			FullName: extraction.StringPtr(subdomain),
		})
	}

	return discovery, nil
}

// inferRootDomain returns the longest common DNS suffix shared by all entries
// in the list. For the common case where subfinder enumerates a single apex
// domain every result will share the same two-label suffix (e.g. "example.com").
//
// The algorithm:
//  1. Split every subdomain into reversed label segments ("api.example.com" →
//     ["com","example","api"]).
//  2. Walk the reversed label columns left-to-right, keeping only labels that
//     are identical across all entries.
//  3. Re-reverse the surviving labels to recover the root domain string.
//
// If the list contains a single entry, the last two labels of that entry are
// returned as the root domain (the minimal safe assumption).
func inferRootDomain(subdomains []string) string {
	if len(subdomains) == 0 {
		return ""
	}

	// Split each subdomain into reversed label slices.
	reversed := make([][]string, len(subdomains))
	for i, sd := range subdomains {
		labels := strings.Split(sd, ".")
		rev := make([]string, len(labels))
		for j, l := range labels {
			rev[len(labels)-1-j] = l
		}
		reversed[i] = rev
	}

	// Single entry: return last two labels as the root.
	if len(reversed) == 1 {
		parts := reversed[0]
		if len(parts) >= 2 {
			// parts are reversed, so parts[0] = TLD, parts[1] = SLD.
			return parts[1] + "." + parts[0]
		}
		return strings.Join(reversed[0], ".")
	}

	// Find the number of common labels from the right.
	minLen := len(reversed[0])
	for _, r := range reversed[1:] {
		if len(r) < minLen {
			minLen = len(r)
		}
	}

	commonDepth := 0
	for i := 0; i < minLen; i++ {
		label := reversed[0][i]
		allMatch := true
		for _, r := range reversed[1:] {
			if r[i] != label {
				allMatch = false
				break
			}
		}
		if !allMatch {
			break
		}
		commonDepth++
	}

	// commonDepth is the number of shared trailing labels. Require at least 2
	// (TLD + SLD) so we always produce a usable root.
	if commonDepth < 2 {
		commonDepth = 2
	}

	// Re-reverse the common suffix labels to form the root domain string.
	common := reversed[0][:commonDepth]
	labels := make([]string, commonDepth)
	for i, l := range common {
		labels[commonDepth-1-i] = l
	}
	return strings.Join(labels, ".")
}
