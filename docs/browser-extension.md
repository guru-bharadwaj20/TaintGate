# Browser origin adapter prototype

`browser_value` labels response text as untrusted and records a normalized
HTTP(S) origin plus the response URL as hashed provenance. Public pages default
to public readers; authenticated/private pages must receive owner reader sets
from trusted configuration. The caller must provide the actual final transport
URL after redirects. This adapter does not fetch pages, verify TLS, enforce
network egress or make a web origin trustworthy. A page-supplied URL cannot
serve as an authenticated origin claim.
