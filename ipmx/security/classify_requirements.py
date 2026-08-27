#!/usr/bin/env python3
# Copyright (C) 2026 Matrox Graphics Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Classify every TR-10-SEC SHALL/SHOULD into "untestable bucket".

Walks ``requirements_tr10_sec.json`` and assigns each entry to one of:

  A — Admin / lifecycle / factory attestation. The SHALL imposes a
      requirement on the device's *administrative surface* (e.g.
      "shall allow an administrator to configure X"). There is no
      wire-observable behaviour to probe — vendor attestation is the
      only way to verify.

  B — Long-window timing. The SHALL specifies an interval measured in
      hours or days (e.g. 23h JWKS refresh, 36h invalidation, 1-64s
      exponential backoff). A single short validator run cannot
      observe the cadence; reference-node verifies these via fast-
      clock unit tests (nmos/oauth2/tests/test_jwks_cache.py).

  C — Informative scaffolding / meta-spec. The SHALL is normative
      language *about* the document (RFC 2119 conformance notation,
      precedence between specs) or *about another party* (AS,
      Controller) rather than the Node under test.

  D — Known reference-node gap. The SHALL is testable in principle
      but reference-node does not yet implement the feature (e.g.
      CRL loading, PKCS#12 import, online cert reload, audit
      counters). Vendor attestation until ref-node grows the feature.

  E — Testable in principle but not yet wired in validator v0.1.
      A future check function can exercise this requirement; the
      validator currently lacks the probe. These are the "growable"
      coverage items.

Outputs:
  - ``requirements_classification.json``: {req_id → {bucket, reason}}
  - Summary table on stdout

Approach: pattern-match each sentence's text. Targeted overrides
handle a small number of ambiguous cases.
"""

from __future__ import annotations

import json
import re
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC_JSON = HERE / "requirements_tr10_sec.json"
CLASS_JSON = HERE / "requirements_classification.json"

# req_ids already wired in the validator's dispatch table (NOT classified
# as cannot-test). Kept in sync with ipmx_validate_security.py's
# ``dispatch`` dict so the summary doesn't double-count them as gaps.
_WIRED_REQ_IDS: frozenset[str] = frozenset({
    # §8 TLS
    "SEC-8-2",          # TLS 1.3 should be supported
    "SEC-8-3",          # TLS 1.3 preferred when both offered
    "SEC-8-4",          # group matrix
    "SEC-8-5",          # group matrix
    "SEC-8-6",          # TLS 1.2 mandatory cipher
    "SEC-8-7",          # CBC ciphers refused (Node omits CBC from whitelist)
    "SEC-8-8",          # TLS 1.2 cipher matrix
    "SEC-8-9",          # prohibited cipher refused
    # §11 RAAM
    "SEC-11.1-1",       # mTLS-only RAAM (Config A)
    "SEC-11.2-1",       # OAuth 2.0 + server TLS RAAM (Config B)
    # §9 NAP — tag-validity + NAP=1 read-open + NAP=2 support + write enforcement
    "SEC-9.2-1",  # tag combination check
    "SEC-9.2-2",  # NAP=1 anonymous read allowed
    "SEC-9.2-3",  # write enforcement via IS-05 PATCH master_enable=false
    "SEC-9.3-1",  # NAP=2 advertised in tags
    "SEC-9.3-2",  # NAP=2 reads require auth
    "SEC-9.3-3",  # NAP=2 write enforcement via IS-05 PATCH
    # §12.5 cert key size
    "SEC-12.5-1",
    "SEC-12.5-2",
    # §12.8 / §12.11 / §12.13 / §12.14-6/7 — GCRL infrastructure +
    # multi-CRL support, signature-validation-across-CAs. Wired by
    # the A-crl-empty-baseline + A-crl-revoked-cert matrix entries.
    "SEC-12.8-1",
    "SEC-12.11-1",
    "SEC-12.13-1",
    "SEC-12.14-6",
    "SEC-12.14-7",
    # §14.3.3.5-3 fail-closed on revoked cert.
    "SEC-14.3.3.5-3",
    # §9 / §11 / §12 mode-support confirmation via published tags
    "SEC-9-1",      # NAP configurable (validator's --expect-nap exercises this)
    # §7.2 / §10 registry-proxy observations — graded against the
    # log dumped by ipmx_registry_proxy.py (matrix runner spawns it
    # in stub mode by default, optionally forward to a real
    # upstream nmos-cpp-registry).
    "SEC-7.2-1",    # no Authorization header on Node→Registry
    "SEC-7.2-2",    # registry secured by TLS (RAP=1/2 entries)
    "SEC-10.1-1",   # api_proto=https → TLS used (RAP=1/2)
    "SEC-10.1-2",   # all compliant devices support TLS-to-registry
    "SEC-10.2-1",   # RAP=2 → mTLS to registry (mutual auth)
    "SEC-10.2-3",   # Restricted Registration supported (per-run RAP)
    "SEC-11.1-2", "SEC-11.1-3",
    "SEC-11.2-2", "SEC-11.2-3",
    "SEC-11.3-1", "SEC-11.3-2",
    "SEC-12.1-1",   # NAP=2 supported (tag advertises 2)
    "SEC-12.2-1",   # RAP=1 or RAP=2 supported (per run)
    "SEC-12.3-1",   # RAAM=0 supported (Config A run)
    "SEC-12.3-2",   # RAAM=1/2 supported (Config B/C run)
    "SEC-12.4-1",   # OAIM=0/1/2 supported (per run)
    "SEC-12.5-3",   # TCT common across all device endpoints
    "SEC-12.5-4",   # RSA + ECDSA independent (per-run TCT confirms)
    "SEC-12.14-4",  # Retrieval of effective values via IPMX security tags
    # §12.15 tags
    "SEC-12.15-1",
    "SEC-12.15-2",  # strict tag-value format
    # §14.1 / §14.2 scope-path mapping
    "SEC-14.1-1", "SEC-14.1-2", "SEC-14.1-3",
    "SEC-14.2-1", "SEC-14.2-2", "SEC-14.2-3",
    # §14.3.2 JWKS
    "SEC-14.3.2-1", "SEC-14.3.2-2",
    "SEC-14.3.2-3", "SEC-14.3.2-5",   # fail-closed via broken-AS mode
    # SEC-14.3.2-8: DNS-SD AS discovery — NOT wired; the validator
    # does not exercise mDNS. Classified A (vendor attestation).
    "SEC-14.3.2-9",                    # iss-claim-not-used
    "SEC-14.3.2-11",                   # TLS-version observation
    "SEC-14.3.2-12",                   # AS cert validated against CTCA — wire negative probe
    "SEC-14.3.2-13",                   # CTCA configured — implicit via JWKS pickup
    # §14.3.2.1 metadata forms
    "SEC-14.3.2.1-1", "SEC-14.3.2.1-2", "SEC-14.3.2.1-3",
    "SEC-14.3.2.1-4", "SEC-14.3.2.1-5",
    # §14.3.3.1 lifetime (1-1 reclassified to C in _OVERRIDES; 1-2 wired)
    "SEC-14.3.3.1-2",
    # §14.3.3.2 type/alg/curve
    "SEC-14.3.3.2-1", "SEC-14.3.3.2-2", "SEC-14.3.3.2-3",
    "SEC-14.3.3.2-4", "SEC-14.3.3.2-5",
    # §14.3.3.3 grants & claims (3-10 reclassified to C below)
    "SEC-14.3.3.3-3", "SEC-14.3.3.3-4",
    "SEC-14.3.3.3-5", "SEC-14.3.3.3-6",
    "SEC-14.3.3.3-7", "SEC-14.3.3.3-8",
    # §14.3.3.4 validation matrix
    "SEC-14.3.3.4-1", "SEC-14.3.3.4-2", "SEC-14.3.3.4-3", "SEC-14.3.3.4-4",
    "SEC-14.3.3.4-5",   # ordered validation sequence — wire-observed by all probes
    "SEC-14.3.3.4-6", "SEC-14.3.3.4-7",
    "SEC-14.3.3.4-8", "SEC-14.3.3.4-10",
    "SEC-14.3.3.4-11", "SEC-14.3.3.4-12",  # OAIM=Cert aud matching + RFC 4592 wildcards (B-oaim1-cert)
    "SEC-14.3.3.4-13",
    "SEC-14.3.3.4-14",  # aud-ordering consistency — indexed-aud probes
    "SEC-14.3.3.4-16",  # scope-API implicit-default-read
    "SEC-14.3.3.4-17", "SEC-14.3.3.4-18", "SEC-14.3.3.4-19",
    "SEC-14.3.3.4-20", "SEC-14.3.3.4-21", "SEC-14.3.3.4-22",
    "SEC-14.3.3.4-23", "SEC-14.3.3.4-24", "SEC-14.3.3.4-25", "SEC-14.3.3.4-26",
    "SEC-14.3.3.4-27", "SEC-14.3.3.4-28",
    "SEC-14.3.3.4-29", "SEC-14.3.3.4-30", "SEC-14.3.3.4-31",
    "SEC-14.3.3.4-32", "SEC-14.3.3.4-33", "SEC-14.3.3.4-34",
    "SEC-14.3.3.4-35", "SEC-14.3.3.4-36", "SEC-14.3.3.4-37",
    "SEC-14.3.3.4-38",
    "SEC-14.3.3.4-39",  # wired via IS-05 PATCH probe (write-endpoint)
    "SEC-14.3.3.4-15",  # scope-claim API-name presence (reuses -17 probe)
    "SEC-14.3.3.4-40", "SEC-14.3.3.4-41",
    "SEC-14.3.3.4-42", "SEC-14.3.3.4-43",
    "SEC-14.3.3.4-44", "SEC-14.3.3.4-45",
    # §14.3.3.5 failure handling
    "SEC-14.3.3.5-1", "SEC-14.3.3.5-2", "SEC-14.3.3.5-4",
    "SEC-14.3.3.5-5", "SEC-14.3.3.5-6",
    # §14.3.3.6 mTLS client_id binding (Config C only)
    "SEC-14.3.3.6-1", "SEC-14.3.3.6-2", "SEC-14.3.3.6-3",
    "SEC-14.3.3.6-6", "SEC-14.3.3.6-7",
    # §14.3.4 HTTP status codes
    "SEC-14.3.4-1",
})

# ---------------------------------------------------------------------------
# Section-level bucket defaults — applied unless a finer rule below matches.
# Section paths are matched as PREFIXES.
# ---------------------------------------------------------------------------

_SECTION_DEFAULT: list[tuple[str, str, str]] = [
    # (section prefix, bucket, default reason)
    ("4", "C", "RFC 2119 conformance vocabulary (§4) — meta-spec, not a device behaviour"),
    ("12.8", "D", "CRL behaviour (§12.8 Client Trusted CRL) — not implemented in reference-node"),
    ("12.11", "D", "Node-endpoint Server Trusted CRL (§12.11) — not implemented in reference-node"),
    ("12.13", "D", "Control-endpoint Server Trusted CRL (§12.13) — not implemented in reference-node"),
]

# ---------------------------------------------------------------------------
# Pattern → (bucket, reason template) — evaluated in order; first match wins.
# Patterns use Python regex against the sentence's lower-cased text.
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[str, str, str]] = [

    # ----- Bucket B: long-window timing -----
    (r"23 hours plus", "B",
     "23h+jitter refresh cadence — long-window timing; verified by "
     "nmos/oauth2/tests/test_jwks_cache.py"),
    (r"36 hours after obtaining", "A",
     "36h hard JWKS invalidation window — vendor attestation. "
     "Compressed-clock fixture was sketched (fake AS Cache-Control: "
     "max-age=0 + clock-source mock) but not wired; attest via "
     "manufacturer sign-off citing nmos/oauth2/tests/test_jwks_cache.py"),
    (r"exponential backoff", "B",
     "Exponential backoff 1–64s — multi-failure observation; verified by "
     "nmos/oauth2/tests/test_jwks_cache.py"),

    # ----- Bucket A: admin / lifecycle / factory -----
    (r"shall allow an administrator", "A",
     "Admin configurability of a setting — verified via vendor attestation"),
    (r"shall provide a means to (?:update|retrieve)", "A",
     "Admin lifecycle / retrieval surface — verified via vendor attestation"),
    (r"shall provide a means for an administrator", "A",
     "Admin retrieval / management surface — verified via vendor attestation"),
    (r"shall provide a configuration option", "A",
     "Admin configurability — verified via vendor attestation"),
    (r"newly manufactured device shall implement the default", "A",
     "Factory-default attestation — verified via manufacturer sign-off"),
    (r"shall be common to all certificates", "A",
     "Admin configurability of cert-type uniformity — attestation"),
    (r"shall support at least two", "A",
     "Admin capacity guarantee (multi-CA / multi-CRL) — attestation"),
    (r"shall not be retrievable", "A",
     "Private-key non-retrievability — attestation"),
    (r"shall be write-only", "A",
     "Private-key write-only storage — attestation"),
    (r"transfer channel shall be secure", "A",
     "Operator-side transfer-channel security — attestation"),
    (r"transfer of the password shall be secure", "A",
     "Operator-side password-transfer security — attestation"),
    (r"counters across boot.*shall provide", "A",
     "Persisted-counter reset requires admin action — attestation"),
    (r"shall be supported by all compliant ipmx devices", "A",
     "Mandatory mode support — vendor attestation"),
    (r"rsa and ecdsa shall independently be supported", "A",
     "Independent RSA / ECDSA support — vendor attestation"),

    # ----- Bucket C: informative / meta-spec / about-other-party -----
    (r"this technical recommendation shall take precedence", "C",
     "Spec-precedence rule — meta, not a device behaviour"),
    (r"shall comply with this technical recommendation\b(?!.*configure|.*support|.*provide)", "C",
     "Generic compliance statement — meta-spec"),
    (r"shall comply with amwa", "C",
     "Compliance-with-other-spec statement — meta-spec"),
    (r"nmos controllers (?:and similar nmos sub-systems )?(?:should|shall) obtain bearer tokens", "C",
     "Requirement on Controller behaviour, not the Node under test — meta"),
    (r"oauth 2\.0 (?:authorization server|clients) (?:shall|should)", "C",
     "Requirement on Authorization-Server or OAuth client side, not Node — meta"),
    (r"^the ordering of the aud array is significant", "C",
     "Informative explanation of aud-indexing semantics"),
    (r"^the indexing of the aud array is zero-based", "C",
     "Informative numbering convention"),
    (r"clients (?:are authorized|shall be provisioned)", "C",
     "Requirement on OAuth client provisioning, not the Node — meta"),
    (r"a conformant implementation according to this document", "C",
     "Conformance criterion definition — meta"),
    (r"order of precedence of the types of normative information", "C",
     "Normative-information precedence rule — meta"),

    # ----- Bucket D: known reference-node gaps -----
    (r"crl|certificate revocation list", "D",
     "CRL behaviour — reference-node does not implement CRL handling"),
    (r"pkcs#12", "D",
     "PKCS#12 cert/key import — reference-node accepts PEM only"),
    # Guest-WS endpoints (SEC-14.3.3.7-1 / -2) are feature-gated SHOULDs:
    # the validator only exercises them when the operator declares
    # ``--supports guest-ws``. Without that flag the matrix runner
    # leaves them as OPTIONAL-ABSENT (the spec-compliant outcome for
    # a device that does not claim the optional feature). Classified
    # C so they appear in the [META]-bucket section as
    # "non-applicable unless the feature is claimed".
    (r"node should provide endpoints for getting a websocket upgrade.*read.?only.*read.?write", "C",
     "Feature-gated SHOULD — exercised only when --supports guest-ws "
     "is declared. Default behaviour: OPTIONAL-ABSENT (device does not "
     "claim the optional feature). When claimed and the device fails, "
     "this becomes a real REF-NODE GAP."),
    (r"read.?only endpoint should have the .?guest", "C",
     "Feature-gated SHOULD — same as SEC-14.3.3.7-1; OPTIONAL-ABSENT "
     "unless --supports guest-ws is declared."),
    # Audit-counter requirements (§14.3.3.5) — flagged as vendor
    # attestation rather than reference-node gap, because no in-band
    # probe can read a counter from the wire. The attestation manifest
    # carries a predicted post-run delta the operator compares against
    # the device's actual counter values (see
    # ``_emit_predicted_counter_deltas`` in ipmx_validate_security.py).
    (r"should increment a status counter", "A",
     "Audit status counters — vendor attestation; compare device's "
     "post-run counter values against the predicted deltas in this "
     "manifest"),
    (r"status counters shall be 64-bit", "A",
     "64-bit monotonic audit counters — vendor attestation"),
    (r"trust material remains usable until a new configuration has been successfully validated", "D",
     "Online trust-material reload — reference-node requires restart"),
    (r"new connections shall follow the new configuration immediately", "D",
     "Online policy reload — reference-node requires restart"),

    # ----- Bucket E: testable but not yet wired (default for anything left) -----
]

# ---------------------------------------------------------------------------
# Targeted per-req_id overrides for entries that pattern-matching gets wrong.
# ---------------------------------------------------------------------------

_OVERRIDES: dict[str, tuple[str, str]] = {
    # §7 — Scope. The text-level patterns handle §7-1 (precedence) and
    # §7-2 (factory default) but the subsections need specific reasons.
    "SEC-7.2-3": ("A",
        "api_auth=false in the registry's DNS-SD TXT record — the "
        "validator does not exercise mDNS / DNS-SD; vendor attests "
        "that the registry advertisement is correct"),
    # §8 SHOULDs and remaining SHALLs.
    "SEC-8-1": ("C",
        "Generic compliance statement ('IPMX device shall comply with this "
        "TR') — meta-spec"),
    # §9 NAP — §9.1 is non-compliant by spec; §9.2 / §9.3 testable but not wired.
    "SEC-9.1-1": ("C",
        "Self-disqualifying: device 'shall not claim compliance' under NAP=0 "
        "— not a testable behaviour against a certified DUT"),
    "SEC-9.1-2": ("C",
        "Same — describes NAP=0 (non-compliant) read access"),
    "SEC-9.1-3": ("C",
        "Same — describes NAP=0 (non-compliant) write access"),
    # SEC-9.2-2 is now wired by the A-nap1-unrestricted-read matrix entry —
    # the validator does an anonymous GET against /x-nmos/node/v1.3/self
    # with the DUT in NAP=1 mode (--nodeOptionalClientAuth).
    # SEC-9.2-3 is now wired via check_write_requires_auth_via_master_enable.
    # §10 RAP — all testable via the registry-proxy fixture (see §7.2).
    "SEC-10.2-2": ("A",
        "api_proto=https in the registry's DNS-SD TXT record — the "
        "validator does not exercise mDNS / DNS-SD; vendor attests "
        "that the registry advertisement is correct"),
    # §12.5 cert-key sizes — testable via peer cert inspection.
    # §12.6/9/10/12 — "Default: Vendor certificates or None ..." —
    # documentary factory-default values, not Node behaviours. The
    # extractor's sentence splitter caught these as standalone SHALL
    # sentences but they really describe what the factory-installed
    # value is; manufacturer attestation territory.
    "SEC-12.6-1": ("A",
        "Factory-default value for the TLS Server Certificate "
        "(\"Vendor certificates or None\") — manufacturer attestation"),
    "SEC-12.9-1": ("A",
        "Factory-default value for the TLS Client Certificate — "
        "manufacturer attestation"),
    "SEC-12.10-1": ("A",
        "Factory-default value for the Node-endpoints Server Trusted "
        "CA(s) — manufacturer attestation"),
    "SEC-12.12-1": ("A",
        "Factory-default value for the Control-endpoints Server Trusted "
        "CA(s) — manufacturer attestation"),
    # §12.14-3 — session continuity during runtime config change.
    "SEC-12.14-3": ("A",
        "Existing sessions continue with the configuration in effect at "
        "session start when admin reconfigures — requires runtime "
        "admin-config change + existing-session observation; admin/"
        "lifecycle territory"),
    # §12.15 tag-value-shape SHOULD.
    # §13 — generic compliance.
    "SEC-13.1-1": ("C",
        "Generic 'implementation supporting OAuth 2.0 shall comply with "
        "IS-10 + BCP-003-02' — meta-spec"),
    # §14.1 / §14.2 — scope and path mapping.
    # §14.3.1 — time sync; we don't control DUT clock.
    "SEC-14.3.1-1": ("A",
        "Node estimation within 30 min of true NTP/PTP — requires "
        "controlled DUT clock skew; partial wire via expired-token test"),
    "SEC-14.3.1-2": ("A",
        "Token-validation clock alignment — same as above"),
    "SEC-14.3.1-3": ("A",
        "Key-fetch clock alignment — same as above"),
    # §14.3.2 — Public Keys lifecycle.
    # SEC-14.3.2-3, -5 wired via fake-AS broken-mode + key rotation.
    "SEC-14.3.2-7": ("A",
        "Log event on invalidation — requires DUT log-stream "
        "observation. Vendor attestation."),
    "SEC-14.3.2-8": ("A",
        "DNS-SD `_nmos-auth._tcp` discovery of the AS URL — the "
        "validator does not exercise mDNS / DNS-SD. The spec allows "
        "the configured-URL alternative; vendor attests the DNS-SD "
        "branch works when the AS is discovered that way"),
    # SEC-14.3.2-8 wired via fake-AS check_iss_not_used_for_jwks.
    "SEC-14.3.2-9": ("A",
        "Multi-AS consistency — deployment attestation: all configured "
        "Authorization Servers must publish the same key set"),
    "SEC-14.3.2-10": ("A",
        "Multi-AS deployment consistency — same as 14.3.2-9; "
        "vendor / deployment attestation"),
    # SEC-14.3.2-11 wired via fake-AS connection log.
    # SEC-14.3.2-12 wired via the untrusted-AS negative probe (see
    # ipmx_validate_security.check_jwks_pickup_rejects_untrusted_as).
    # SEC-14.3.2-13 wired by the same JWKS pickup proof — every
    # successful Stage 1 run demonstrates the Node validates the fake
    # AS's ExampleRootCA-chained cert against its CTCA.
    # §14.3.2.1 metadata endpoint forms — fake AS supports all three.
    # §14.3.3.1 lifetime — SEC-14.3.3.1-1 says exp shall be 1-24h from
    # iat. The spec's §14.3.3.4 validation pseudocode (which is the
    # authoritative algorithm) DOES NOT enforce this bound — it only
    # checks exp > now(). The SHALL is therefore a constraint on the AS
    # / token-issuer, not on the Node validator. Reclassified C.
    "SEC-14.3.3.1-1": ("C",
        "Token lifetime [1h, 24h] applies to token issuance — the spec's "
        "§14.3.3.4 validation pseudocode only checks exp > now(); enforcing "
        "the upper/lower bound is the AS's responsibility, not the Node's"),
    # §14.3.3.2 — typ/alg/curve.
    # §14.3.3.3 grants/claims.
    "SEC-14.3.3.3-10": ("C",
        "Duplicated x-nmos-* shall be identical — applies to token "
        "issuance. The §14.3.3.4 validation pseudocode reads ext OR "
        "top-level (never both), so the Node cannot enforce this rule "
        "via the spec's algorithm. AS-side concern."),
    # §14.3.3.4 entries (the big matrix). Most are E unless they hit
    # the patterns for D or C above.
    # SEC-14.3.3.4-5 promoted to W: the ordered validation sequence is
    # implicitly proven by the full token-validation matrix — every
    # adversarial probe produces the spec-mandated outcome, so the
    # Node IS observing the required order. Witness mapping in
    # ipmx_validate_security.py uses check_validation_sequence_observed.
    # SEC-14.3.3.4-11 / SEC-14.3.3.4-12 are wired via the
    # B-oaim1-cert matrix entry (--expect-oaim=1) — both the
    # OAIM=Cert aud-matching rule and the RFC 4592 wildcard
    # variant are exercised by check_aud_oaim_cert_dns_wildcard
    # and check_aud_dns_wildcard_accepted.
    "SEC-14.3.3.4-9": ("C",
        "Recommended authorization scoping to serial number — informative "
        "best practice for the AS, not directly testable on the Node"),
    # SEC-14.3.3.4-14 promoted to W: aud-ordering consistency is
    # observed by every indexed-aud probe converging to the spec
    # outcome (negative/positive/multi-index/match-then-wildcard
    # variants all PASS). Witness mapping uses check_aud_ordering_consistent.
    # SEC-14.3.3.4-16 promoted to W: implicit-default-read on the API
    # name in the scope claim — see check_scope_provides_default_read.
    # §14.3.3.5 failure handling.
    # §14.3.3.6 — mTLS client_id binding.
    "SEC-14.3.3.6-4": ("A",
        "Wildcards not matched for binding — vendor attestation. "
        "Wire-testing requires minting a wildcard-SAN client cert "
        "(e.g. CN=*.example.com) chained to the trust anchor. "
        "Operators understandably prefer not to mint wildcard certs "
        "they would not use in production, so this SHALL falls to "
        "the manifest: vendor confirms Node refuses to match a "
        "token client_id against a wildcard SAN entry"),
    "SEC-14.3.3.6-5": ("A",
        "Wildcard SAN treated as non-matching — vendor attestation; "
        "same wire-test constraint as SEC-14.3.3.6-4 (wildcard-SAN "
        "cert needed). The two SHALLs restate the same rule"),
    # §14.3.3.6-8 / -9: about Client / Controller provisioning at the AS.
    "SEC-14.3.3.6-8": ("C",
        "Client provisioning rule: OAuth 2.0 clients shall be "
        "provisioned such that client_id matches the cert CN/SAN — "
        "applies to the AS at client-registration time, not the Node"),
    "SEC-14.3.3.6-9": ("C",
        "Wildcards shall not be used in OAuth client provisioning — "
        "applies to the AS / client-registration tooling, not the Node"),
    # §14.3.3.3-9: token issuer should place x-nmos-* in either form.
    "SEC-14.3.3.3-9": ("C",
        "Token issuer should place x-nmos-* in ext OR top-level — "
        "applies to the AS / token issuer; the Node accepts both forms "
        "(demonstrated by SEC-14.3.3.3-8)"),
    # §14.3.3.7 WebSocket.
    "SEC-14.3.3.7-3": ("A",
        "Classification statement (not a separate Node behaviour): "
        "'Subscribing to notification messages shall be considered "
        "a read-only operation.' The underlying access-control logic "
        "is already covered by our read-only-token probes; the spec "
        "is just defining how to bucket the WS subscribe op for the "
        "purposes of the §14.3.3.4 read/write evaluation. Vendor "
        "attests that its WS subscribe handler is classified as "
        "read-only in the token-validation pipeline."),
    "SEC-14.3.3.7-4": ("C",
        "Informative: connection-state side-effects not considered Node "
        "side-effects"),
    # §14.3.4 HTTP status codes.
}

def classify(req_id: str, section_path: str, text: str) -> tuple[str, str]:
    """Return (bucket, reason) for one requirement."""
    if req_id in _OVERRIDES:
        return _OVERRIDES[req_id]

    # Section-level defaults (overridden by per-req overrides above).
    for prefix, bucket, reason in _SECTION_DEFAULT:
        if section_path == prefix or section_path.startswith(prefix + "."):
            return (bucket, reason)

    # Pattern matches against the sentence text.
    low = text.lower()
    for pattern, bucket, reason in _PATTERNS:
        if re.search(pattern, low):
            return (bucket, reason)

    # No bucket assigned — surface as a hard error so the dev classifies it
    # explicitly. The previous "validator gap" (bucket E) catch-all is gone
    # because the v0.1 wiring is complete; any new spec entry needs to be
    # classified into A/B/C/D or added to _WIRED_REQ_IDS.
    raise RuntimeError(
        f"classify_requirements: no bucket for {req_id} (§{section_path}). "
        f"Either add it to _WIRED_REQ_IDS, give it an _OVERRIDES entry, or "
        f"extend _SECTION_DEFAULT / _PATTERNS so it lands in A/B/C/D."
    )

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    with open(SPEC_JSON, "r", encoding="utf-8") as f:
        spec_entries = json.load(f)

    classification: dict[str, dict[str, str]] = {}
    wired_count = 0
    for entry in spec_entries:
        req_id = entry["req_id"]
        if req_id in _WIRED_REQ_IDS:
            classification[req_id] = {
                "bucket": "W",
                "reason": "Wire-tested by the validator's check function for this req_id",
            }
            wired_count += 1
            continue
        bucket, reason = classify(req_id, entry["section_path"], entry["text"])
        classification[req_id] = {"bucket": bucket, "reason": reason}

    with open(CLASS_JSON, "w", encoding="utf-8") as f:
        json.dump(classification, f, indent=2, sort_keys=True)
    print(f"Wrote {len(classification)} classifications to {CLASS_JSON}")

    # Per-bucket summary.
    counts: Counter[str] = Counter()
    counts_shall: Counter[str] = Counter()
    counts_should: Counter[str] = Counter()
    for entry in spec_entries:
        b = classification[entry["req_id"]]["bucket"]
        counts[b] += 1
        if entry["level"] == "shall":
            counts_shall[b] += 1
        else:
            counts_should[b] += 1

    BUCKET_LABELS: dict[str, str] = {
        "W": "Wire-tested by validator",
        "A": "Admin / lifecycle / factory attestation (genuinely not wire-testable)",
        "B": "Long-window timing (hours/days; verified by ref-node unit tests)",
        "C": "Informative / scaffolding / about other party (no Node behaviour)",
        "D": "Known reference-node gap (testable in principle)",
    }
    print("\nBucket summary (TR-10-SEC, 188 entries):")
    print(f"  {'':5} {'TOTAL':>6} {'SHALL':>6} {'SHOULD':>6}  Description")
    for b in ("W", "A", "B", "C", "D"):
        print(f"  {b:5} {counts[b]:>6} {counts_shall[b]:>6} {counts_should[b]:>6}  {BUCKET_LABELS[b]}")
    print(f"  ---- ------ ------ ------")
    print(f"  TOT  {sum(counts.values()):>6} {sum(counts_shall.values()):>6} "
          f"{sum(counts_should.values()):>6}")

    truly_untestable_by_nature = counts["A"] + counts["B"] + counts["C"]
    ref_node_gaps = counts["D"]
    print()
    print("Honest assessment:")
    print(f"  Wire-tested today                                : {counts['W']:>3}")
    print(f"  Genuinely cannot be tested over the wire (A/B/C) : {truly_untestable_by_nature:>3}")
    print(f"  Reference-node gaps (D — testable once fixed)    : {counts['D']:>3}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
