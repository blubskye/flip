# FLIP TODO

## Channel Message Encryption

**Status:** Not implemented — design decision needed

Channel messages are currently posted as plaintext SSK-signed payloads to Freenet.
Anyone polling the sender's SSK can read them. Private messages (PMs) use RSA
encryption, but no equivalent exists for channel traffic.

### Proposed design

Since FLIP has no shared symmetric channel key, encryption must be per-recipient:

1. `StartChannelInsert()` in `freenetmessageinserter.cpp` loops over all known
   members of the target channel (from `tblIdentity` / channel membership state).
2. For each member, RSA-encrypt the message body with their public key (OAEP by
   default; PKCS#1 v1.5 if `m_legacycompat` is set for that identity).
3. Post one ciphertext blob per recipient inside the Freenet message payload, each
   tagged with the recipient's public key fingerprint so the downloader knows which
   blob to attempt decryption on.
4. Receiver (`freenetmessagedownloader.cpp`) tries to decrypt each blob whose
   fingerprint matches a local identity's private key.

### Trade-offs

- Message size grows linearly with channel membership — large channels will produce
  large Freenet inserts.
- Channel name and member list remain visible in the SSK URI and join messages
  (unavoidable without a separate channel membership protocol).
- Members who join after a message is posted cannot decrypt it retroactively (no
  forward delivery for late joiners, same as current PM behaviour).
- Legacy channels (`/legacy #channel`) should use PKCS#1 v1.5 for all recipient
  blobs so old clients can decrypt.

### Files to change

| File | Change |
|---|---|
| `src/freenet/freenetmessageinserter.cpp` | `StartChannelInsert()` — encrypt per member |
| `src/freenet/freenetmessageinserter.h` | signature update if needed |
| `src/freenet/freenetmessagedownloader.cpp` | decrypt blob matching local identity key |
| `src/irc/ircserver.cpp` | pass `m_legacychannels` state to inserter |

---

## Other (from todo_flip.txt)

- Disable CTCP replies (CTCP suppression already added for forwarding; verify local
  client auto-reply is also suppressed)
