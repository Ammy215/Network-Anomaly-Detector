# Port scan behavioral signature

> Internal reference doc for this project's RAG knowledge base. Connects
> network-fundamentals theory directly to the exact 8 features
> NetSentinel's shipped model (`isolation_forest`, `behavioural_only`
> variant) computes — see `docs/ML-MODEL-NOTES.md` for the model's
> measured performance and honest limitations.

## What a port scan literally does

A port scanner (nmap being the canonical example) sends a connection
attempt — typically a TCP SYN packet — to many destination ports on a
target host, one after another, usually within a short time window. The
goal is to enumerate which ports have something listening (open),
nothing listening (closed), or are silently dropped by a firewall
(filtered). This is mapped in MITRE ATT&CK as Active Scanning (T1595)
under the Reconnaissance tactic, and the host-side response to it as
Network Service Discovery (T1046) under Discovery.

## Why a closed-port probe produces a distinctive flow

When a SYN arrives at a port with no listening service, the target's own
TCP/IP stack — not any application — immediately replies with a RST.
This happens automatically, at the operating-system level, milliseconds
after the SYN arrives. No SYN-ACK is ever sent, so no handshake ever
begins completing.

In NetSentinel's own vocabulary (see the handshake-and-close-semantics
note): this flow gets `handshake_completed = false` and
`close_type = rst`. Packets did travel in both directions — the scanner's
SYN, and the target's RST — so `is_bidirectional` is still `true` even
though no real application-layer exchange occurred. A single scan probe
against a closed port is, from the target's perspective, exactly two
packets: one in, one out, no handshake, reset close.

## Why this generalises across many probes without needing timing features

A fast scan produces hundreds or thousands of flows that all share this
exact same three-feature signature (`is_bidirectional=true`,
`handshake_completed=false`, `close_type=rst`) against many different
destination ports from the same source in a short window. The *port
fan-out* — one source touching an unusually large number of distinct
destinations on one target — is the pattern a human analyst would notice
first. NetSentinel's shipped model doesn't directly compute a fan-out
count as a feature; it relies on each individual probe's own three-value
signature being unusual relative to normal traffic, which turns out to
be sufficient on its own (see `docs/ML-MODEL-NOTES.md`'s evidence that
this signal is path-independent).

## Why timing and packet-size features were deliberately dropped

An earlier version of this model also used timing-based features
(duration, packets/second, bytes/second, average packet size). Ablation
testing showed the handshake/close-type signature alone detected scans
just as well — in fact better across different capture paths — while
timing features made the model *less* portable, because raw packet
timing is sensitive to the specific machine and network path a capture
was taken on, not just to the behaviour itself. `docs/ML-MODEL-NOTES.md`
documents this decision and its supporting evidence directly.

## What this signature does not tell you

Matching this signature is evidence consistent with a port scan — it is
not proof of one, and it is not evidence of what the scan's outcome was.
`docs/ML-MODEL-NOTES.md` documents in detail why a high score here should
never be read as "an attack was confirmed": the same three-feature
pattern can arise from other abrupt, non-cooperative connection failures
that have nothing to do with scanning. Behavioural similarity to a known
scan pattern is exactly that — similarity, not identity.
