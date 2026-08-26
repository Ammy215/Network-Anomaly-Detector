# TCP handshake and close semantics

> Internal reference doc, written for this project's RAG knowledge base.
> It defines the exact vocabulary NetSentinel's flow assembly and feature
> extraction use (`backend/app/services/flow_assembly.py`,
> `backend/app/services/ml/feature_matrix.py`), so a future AI
> explanation can ground itself in the terms our own system outputs,
> not generic textbook language that doesn't match our data.

## The three-way handshake

A TCP connection begins with three packets: the client sends **SYN**
(synchronize — "I want to talk"), the server replies **SYN-ACK**
("acknowledged, I want to talk too"), and the client replies **ACK**
("acknowledged"). Only after all three packets are observed has the
handshake **completed** — meaning both sides have agreed to open a
connection and either side may now send application data.

If a SYN is sent and no SYN-ACK ever comes back, the handshake never
starts completing. If a SYN-ACK comes back but is followed by a RST
instead of an ACK, the handshake was abandoned mid-way. Either way, no
completed handshake occurred, and NetSentinel treats both as the same
outcome for feature purposes: `handshake_completed = false`.

## What `handshake_completed` means in this system

NetSentinel stores `handshake_completed` as a three-state value, not a
boolean, because TCP is not the only protocol it observes:

- **`true`** — the full SYN / SYN-ACK / ACK sequence was observed for
  this flow.
- **`false`** — this is a TCP flow, but the handshake did not complete
  (no SYN-ACK, or a SYN-ACK followed by a reset instead of the closing
  ACK).
- **`not_applicable`** — this flow's protocol has no handshake concept
  at all (UDP is the common case). Collapsing this into `false` would
  wrongly tell a model "every UDP flow failed to connect," which isn't
  a real signal — UDP simply doesn't have a handshake to fail. Keeping
  it a distinct third state is what lets the shipped model treat
  "handshake failed" and "handshake doesn't apply here" as the different
  facts they actually are.

## The four `close_type` values

NetSentinel classifies how a flow ended into exactly four categories:

- **`fin_fin`** — both sides sent a FIN packet, the standard orderly TCP
  close. Each side explicitly said "I'm done sending." This is what a
  normal, completed, cooperative connection looks like at the end.
- **`rst`** — the connection ended with a RST (reset) packet instead of
  a graceful FIN exchange. A RST is an abrupt, non-negotiated
  termination — commonly sent by an operating system's TCP stack the
  instant it receives a SYN on a port with nothing listening, since
  there's no application to hand the connection to. It can also appear
  when an application aborts a connection abnormally.
  **This project deliberately does not claim RST always means an
  attack** — a real application closing early or a firewall rejecting a
  connection can also produce a RST. It's one behavioural signal among
  several, not a verdict by itself. See the port-scan-behavioral-
  signature note for how this signal is actually used.
- **`timeout`** — no closing packet (FIN or RST) was observed before
  NetSentinel's flow-inactivity window elapsed, so the flow was closed
  administratively by the capture pipeline, not by either endpoint.
- **`eof`** — the packet capture itself ended (the file ran out, or live
  capture stopped) before this flow reached any of the other three
  outcomes. This is a property of *when the capture happened to stop*,
  not of the flow's own behaviour — a flow marked `eof` may have gone on
  to close normally moments after the capture ended.

## Why this vocabulary matters for explanation, not just detection

Every one of the 8 features NetSentinel's shipped model
(`isolation_forest`, `behavioural_only` variant) actually uses is built
from this vocabulary: `is_bidirectional`, one-hot encodings of the three
handshake states, and one-hot encodings of the four close types — nothing
else. A model explanation that says "this flow's `close_rst` feature was
1.0" is only useful to an analyst if they know a RST means an abrupt,
non-cooperative termination, not a normal disconnect. This document is
what lets a future AI explanation translate the model's internal feature
names back into what actually happened on the wire.
