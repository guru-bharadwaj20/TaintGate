# Outbound filtering

Outbound sinks include tool arguments, final responses and browser-rendered link
or image destinations. Reader labels enforce confidentiality independently of
heuristic secret recognition. Scanner matches are alerts, not proof of a secret;
absence of a match never declassifies a value.

Safe Markdown rendering disables raw HTML. Disallowed href/src attributes become
empty strings and carry data-taintgate-blocked=true; visible text/alt text remains.
The output retains its original label: a renderer must still check the recipient
can read that label. Domain matching is exact (subdomains need explicit entries).

PAN and Aadhaar checks recognize formats only. They do not verify issuance,
identity, PAN holder type or Aadhaar checksum; Aadhaar detection requires nearby
context to reduce accidental matches. Card checksum matches likewise do not prove
a real account. Only synthetic values are used in test fixtures.

The ten-line benign fixture in test_dlp_scanners.py produces 0/10 alerts under the
pattern/card/identifier scanner. This small synthetic check is not a population
false-positive estimate. Entropy alerts are opt-in because hashes and random
identifiers often look like keys. Encoded canaries cover percent, hex and base64;
arbitrary encryption, fragmentation or new encodings can evade supplementary
scanners. Labels and recipient checks provide the independent confidentiality rule.
