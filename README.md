# Subfinder Discovery Tool

Passive subdomain enumeration tool using multiple sources for domain reconnaissance.

## Entity Extraction

The subfinder tool extracts the following entities to the GraphRAG knowledge graph:

### Entities

| Entity Type | Description | Key Fields |
|-------------|-------------|------------|
| **Domain** | Root/apex domains | `name`, `registrar`, `created_at` |
| **Subdomain** | Discovered subdomains | `name`, `domain_id`, `source` |

### Relationships

| Relationship Type | From | To | Description |
|-------------------|------|------|-------------|
| `HAS_SUBDOMAIN` | Domain | Subdomain | Domain has a subdomain |

### Entity ID Generation

Entity IDs are deterministically generated using SHA1-based UUIDs for idempotency:

- **Domain**: `uuid5(OID, "domain:{domain_name}")`
- **Subdomain**: `uuid5(OID, "subdomain:{subdomain_name}")`

## Example Graph Structure

```
[Domain: example.com]
    ├── HAS_SUBDOMAIN → [Subdomain: www.example.com]
    ├── HAS_SUBDOMAIN → [Subdomain: api.example.com]
    ├── HAS_SUBDOMAIN → [Subdomain: staging.example.com]
    └── HAS_SUBDOMAIN → [Subdomain: dev.example.com]
```

## Provenance

All relationships include provenance properties:

- `discovered_by`: `"subfinder"`
- `discovered_at`: Unix timestamp (milliseconds)
- `mission_run_id`: Mission context identifier

## Metadata

Extraction metadata includes:

- `domain_count`: Number of apex domains
- `subdomain_count`: Number of subdomains discovered
- `sources_used`: Enumeration sources queried
- `scan_duration`: Total enumeration duration in seconds
