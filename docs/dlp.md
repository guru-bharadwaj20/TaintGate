# Outbound filtering

Outbound sinks include tool arguments, final responses and browser-rendered link
or image destinations. Reader labels enforce confidentiality independently of
heuristic secret recognition. Scanner matches are alerts, not proof of a secret;
absence of a match never declassifies a value.

Safe Markdown rendering disables raw HTML. Disallowed href/src attributes become
empty strings and carry data-taintgate-blocked=true; visible text/alt text remains.
The output retains its original label: a renderer must still check the recipient
can read that label. Domain matching is exact (subdomains need explicit entries).
