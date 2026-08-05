# README Security and Tradeoff Notes

The honest version of what this system does and does not achieve. These notes
belong in front of any reader who might otherwise assume more.

## Inference attacks

Removing direct identifiers does not remove all identifying context. A record
with every name, email, and phone number replaced can still describe exactly one
person. Rare combinations of facts — a diagnosis, a date, an employer, a
location — enable linkage against other data the gateway never sees.

The gateway operates on spans a detector can point at. Identity that lives in
the *combination* of ordinary facts is outside what any span-based control can
reach.

## The vault is a high-value target

The vault contains reversible mappings. Everything else the system protects can
be recovered from it, which makes it the thing worth attacking. It requires
encryption at the application layer, isolation, TTL, destruction on logout,
least privilege, monitoring, and production-grade key management — all of them,
not a selection. See [threat-model.md](threat-model.md).

## Pseudonymization risk

Pseudonymization preserves semantic quality and can preserve relationships and
quasi-identifiers along with it. It is not anonymization, and describing it as
such would be a claim this system cannot support (ADR-0025).

## The semantic quality tradeoff

There is no action that is best everywhere. Each trades utility against
exposure:

| Action | Preserves | Costs |
|---|---|---|
| **Redaction** | Nothing about the value | Removes the most context; answers degrade |
| **Tokenization** | Repeated references and entity type | Requires a stateful, encrypted vault |
| **Pseudonymization** | Natural language quality | Highest inference risk; leaks shape |
| **Blocking** | — | Strongest control; the request does not proceed |

Choosing per entity type is the point of policy-driven actions (ADR-0014).
Blocking is right for the highest-risk categories; tokenization is the sensible
default because it is reversible, so a false positive costs almost nothing while
a miss leaks permanently.

## What this is not

- Not a compliance certification.
- Not a guarantee of perfect detection recall.
- Not full PHI understanding — generic PII detection is a different thing.
- Not protection against a compromised gateway process.
- Not protection against traffic that bypasses the gateway, unless egress is
  enforced at the network.

## Related documents

- [threat-model.md](threat-model.md)
- [audit-evidence.md](audit-evidence.md)
- [data-classification.md](data-classification.md)
