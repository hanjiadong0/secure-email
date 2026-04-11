# P2P Mail Feasibility Exploration

## Question

Can this system evolve from server-relay mail toward a peer-to-peer mail form?

## Short Answer

Partially, but with major tradeoffs.

## Possible P2P Direction

A P2P mail variant would require:
- long-term user identity keys
- direct peer discovery
- NAT traversal strategy
- offline message buffering
- store-and-forward fallback

## Challenges

### Availability

Email users are often offline.

Traditional servers solve this by storing mail until the user reconnects. Pure P2P systems struggle with that unless they add:
- relay peers
- mailbox caches
- delegated storage

### Security

P2P introduces harder trust problems:
- peer identity verification
- metadata leakage
- spam resistance
- denial-of-service control

### Operations

Server-side control becomes weaker:
- harder audit collection
- harder abuse throttling
- harder relay policy enforcement

## Feasible Hybrid Model

A more realistic extension is a hybrid approach:
- keep domain servers for identity, offline storage, and abuse control
- optionally allow direct peer-assisted transfer for large encrypted attachments

This preserves most benefits of the current design while exploring limited P2P behavior.

## Recommendation

For this project, P2P should remain a feasibility study, not the primary runtime design.

That makes it a good bonus discussion item without undermining the assignment's core deliverable.
