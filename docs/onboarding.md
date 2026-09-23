# Tool onboarding

1. Connect an upstream server using an official SDK transport on the trusted host.
2. Choose a unique local server identity and namespace; never copy remote prose
   into a trusted planner signature automatically.
3. Define a local Contract with a bounded JSON input schema and plain description.
4. Assign ServerConfig integrity and reader principals. Results default untrusted.
5. Inspect the advertised metadata and scanner findings. An explicit host approval
   writes a canonical SHA-256 pin to PinStore.
6. Register the contract and configure a policy callback receiving a trusted
   execution context. Missing context defaults deny. Never deserialize a user
   supplied label or approval object as host authority.
7. Exercise an allowed and denied call through the downstream gateway adapter.
8. A changed pin quarantines the tool. Show PinStore.diff and obtain a new explicit
   host approval before MetadataGuard.reapprove.

Names use `server__tool` so they are valid TaintScript identifiers. Store pins
outside attacker-controlled server directories. SDK HTTP deployments need host
session authentication; the bundled web interface is an authenticated dry-run,
not an automatically configured production proxy. Descriptions are heuristic
scan input. Pinning cannot attest remote code or eliminate server-side races.
