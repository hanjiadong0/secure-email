# End-to-End Encryption Design Notes

## Goal

Explore how the current secure email prototype could evolve toward end-to-end encryption while preserving the two-domain architecture.

## High-Level Design

Each user would own:
- a long-term public/private key pair
- a public-key directory entry published through the server

Each message send would use hybrid encryption:
1. generate a random message content key
2. encrypt subject/body/attachment metadata with that content key
3. encrypt the content key separately for each recipient using the recipient public key
4. store and relay only ciphertext plus encrypted content keys

## What Would Change

### Client

The client would need to:
- generate and protect user private keys
- encrypt outgoing content locally
- decrypt incoming content locally
- verify sender signatures

### Server

The server would still:
- authenticate users
- store mailbox metadata
- relay ciphertext
- enforce traffic policy

But it would no longer be able to read message body plaintext.

## Benefits

- stronger privacy against server compromise
- reduced trust in relay/storage layers
- clearer separation between transport security and message confidentiality

## Tradeoffs

This design makes some current features harder:
- server-side keyword extraction
- server-side phishing analysis on message body
- server-side search over plaintext
- quick reply suggestions based on body text

To preserve those features, they would need to move client-side.

## Practical Recommendation

For this project, end-to-end encryption is best documented as a future extension rather than forced into the current MVP.

Reason:
- it is compatible with the architecture
- it raises the design quality
- but it would significantly change the intelligent-feature pipeline
