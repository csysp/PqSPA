Safe integration with existing nftables

Prereqs
- Existing `table inet fw4` (or adjust family/table names).

Validate presence
- `nft list table inet fw4`
- `nft list set inet fw4 wg_spa_allow`

Create set if missing (idempotent pattern)
- `nft add set inet fw4 wg_spa_allow { type ipv4_addr; flags timeout; }`

Rule example (don’t flush rulesets)
- In your `fw4` input chain, allow WG only when source is in the set:
  `udp dport 51820 ip saddr @wg_spa_allow accept`

Notes
- Doorman only adds elements with timeouts. It never modifies tables, chains, or rules.
