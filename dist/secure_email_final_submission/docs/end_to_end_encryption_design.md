# End-to-End Encryption Design Notes

## Goal

Document and explain the current optional end-to-end encryption path that now exists in the secure email prototype.

## High-Level Design

Each user owns:
- a long-term public/private key pair
- a public-key directory entry published through the server

Each encrypted message send uses hybrid encryption:
1. generate a random message content key
2. encrypt subject/body plaintext with that content key
3. encrypt the content key separately for each recipient using the recipient public key
4. store and relay only ciphertext plus encrypted content keys

## What Would Change

### Client

The browser client and CLI now:
- generate and protect user private keys locally
- publish public keys through the authenticated key-directory API
- encrypt outgoing subject/body locally
- decrypt incoming encrypted text locally

### Server

The server still:
- authenticate users
- store mailbox metadata
- relay ciphertext
- enforce traffic policy

But it cannot read end-to-end encrypted subject/body plaintext.

## Current Cryptographic Shape

- curve: `P-256`
- key agreement: ECDH
- KDF: HKDF-SHA256
- payload encryption: AES-256-GCM
- one wrapped content key per recipient

The current implementation stores the envelope inside mailbox rows and relays it
across domains without decryption.

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

That tradeoff already appears in the current implementation: encrypted text
mail is stored with placeholder subject/body on the server, while normal
non-E2E mail still keeps server-side smart features.

## Current Limitation

- E2E mode is text-only for now
- image attachments remain transport-protected and storage-encrypted, but not end-to-end encrypted
- encrypted drafts are not yet supported in the browser UI
