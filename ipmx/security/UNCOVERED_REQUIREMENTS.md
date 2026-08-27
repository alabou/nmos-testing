# TR-10-SEC test suite — Uncovered requirements

_Generated from 206 spec entries. Validator currently PASSes_
_**145/191 SHALL** and **7/15 SHOULD**;_
_this document covers the remaining_
_**43 SHALL + 8 SHOULD** that do NOT yet PASS._

## Summary

| Bucket | SHALL | SHOULD | Total | Why |
|---|---|---|---|---|
| **[ATTEST]** | 26 | 1 | 27 | Admin / lifecycle / factory attestation |
| **[LONG-WINDOW]** | 0 | 1 | 1 | Long-window timing (hours/days) |
| **[META]** | 16 | 6 | 22 | Spec scaffolding / about other party |
| **[REF-NODE GAP]** | 1 | 0 | 1 | Reference-node feature missing |
| | **43** | **8** | **51** | |

## Contents

- [[ATTEST] — 27 entries](#attest)
- [[LONG-WINDOW] — 1 entries](#long-window)
- [[META] — 22 entries](#meta)
- [[REF-NODE GAP] — 1 entries](#ref-node-gap)

---

## [ATTEST] — Admin / lifecycle / factory attestation

**27 entries** (26 SHALL + 1 SHOULD)

These requirements cannot be observed at the network wire. They concern factory defaults, admin-UI capabilities, lifecycle guarantees, counter outputs, or operator-procedure security. The compliance evidence is a manufacturer attestation form.

| ID | § | Level | Spec text |
|---|---|---|---|
| `SEC-7-2` | §7 | SHALL | A newly manufactured device shall implement the default values specified in this Technical Recommendation for all security-relevant configuration options for which defaults are defined. |
| `SEC-7.2-3` | §7.2 | SHALL | api_auth of the Registry DNS-SD record shall be false. |
| `SEC-7.3-1` | §7.3 | SHALL | A device shall provide a configuration option to turn off peer-to-peer mode to prevent any use of mDNS for strict customer security policies. |
| `SEC-10.2-2` | §10.2 | SHALL | api_proto of the Registry DNS-SD record shall be “https” |
| `SEC-12.6-1` | §12.6 | SHALL | Default: Vendor certificates or None (shall be configured in order to enable related configurations) |
| `SEC-12.7-1` | §12.7 | SHALL | Shall support at least two CTCA for each type of access in order to allow certificate re-provisioning. |
| `SEC-12.9-1` | §12.9 | SHALL | Default: Vendor certificates or None (shall be configured in order to enable related configurations) |
| `SEC-12.10-1` | §12.10 | SHALL | Default: Vendor Root CA(s) or None (shall be configured in order to enable related configurations) |
| `SEC-12.12-1` | §12.12 | SHALL | Default: Vendor Root CA(s) or None (shall be configured in order to enable related configurations) |
| `SEC-12.14-1` | §12.14 | SHALL | The device shall provide a means to update trust material such that a valid existing trust configuration remains usable until a new configuration has been successfully validated. |
| `SEC-12.14-3` | §12.14 | SHALL | Existing sessions shall continue with the configuration that was in effect when the session was established until they can safely be terminated. |
| `SEC-12.14-5` | §12.14 | SHALL | Private keys are out of scope for retrievable configuration and shall be write-only and shall not be retrievable. |
| `SEC-12.14-8` | §12.14 | SHALL | When using the PEM format the transfer channel shall be secure. |
| `SEC-12.14-9` | §12.14 | SHALL | When using the PKCS#12 format the transfer of the password shall be secure. |
| `SEC-14.3.1-1` | §14.3.1 | SHALL | The Node estimation of the true time shall be within 30 minutes of the true NTP / PTP time used by the OAuth 2.0 Authorization Server. |
| `SEC-14.3.1-2` | §14.3.1 | SHALL | The estimated time used by the Node to validate the claims of a token shall comply with this requirement. |
| `SEC-14.3.1-3` | §14.3.1 | SHALL | The estimated time used by the Node to schedule the fetch / update of the OAuth 2.0 Authorization Server public keys shall comply with this requirement. |
| `SEC-14.3.2-10` | §14.3.2 | SHALL | All the accessible OAuth 2.0 Authorization Servers shall publish the same set of Public Keys such that any OAuth 2.0 Authorization Server may be used by an NMOS Node to obtain the Public Keys and validate access tokens. |
| `SEC-14.3.2-4` | §14.3.2 | SHALL | An NMOS Node shall invalidate the Public Keys from a previous fetch / update operation 36 hours after obtaining them. |
| `SEC-14.3.2-7` | §14.3.2 | SHALL | An NMOS Node shall log an event if it invalidates the Public Keys and it should log an event when it gets a set of Public Keys. |
| `SEC-14.3.2-8` | §14.3.2 | SHALL | An NMOS Node shall discover through DNS-SD the OAuth 2.0 Authorization Servers URL from the standard IS-10 _nmos-auth._tcp service or it may be configured with a list of URLs. |
| `SEC-14.3.3.4-46` | §14.3.3.4 | SHOULD | An NMOS Node should increment a status counter a) when a ReadOnly access is denied: a.1) based on the sub claim, a.2) based on the aud claim, a.3) based on the scope claim, a.4) based on the x-nmos-* claim, b) when a … |
| `SEC-14.3.3.4-47` | §14.3.3.4 | SHALL | The status counters shall be 64-bit unsigned integers and shall be monotonic (non-decreasing) since boot/reset/restart. |
| `SEC-14.3.3.4-48` | §14.3.3.4 | SHALL | An IPMX device may persist the counters across boot/reset/restart and if so shall provide an administrator a means to reset them through an explicit administrative action. |
| `SEC-14.3.3.6-4` | §14.3.3.6 | SHALL | Wildcards shall not be considered a match. |
| `SEC-14.3.3.6-5` | §14.3.3.6 | SHALL | If a wildcard is present in any SAN entry the Node shall treat it as non-matching for the purpose of this check. |
| `SEC-14.3.3.7-3` | §14.3.3.7 | SHALL | Subscribing to notification messages shall be considered a read-only operation. |

### Detail

**`SEC-7-2`** §7 (SHALL)

> A newly manufactured device shall implement the default values specified in this Technical Recommendation for all security-relevant configuration options for which defaults are defined.

*Why not PASSing today:* Factory-default attestation — verified via manufacturer sign-off

---

**`SEC-7.2-3`** §7.2 (SHALL)

> api_auth of the Registry DNS-SD record shall be false.

*Why not PASSing today:* api_auth=false in the registry's DNS-SD TXT record — the validator does not exercise mDNS / DNS-SD; vendor attests that the registry advertisement is correct

---

**`SEC-7.3-1`** §7.3 (SHALL)

> A device shall provide a configuration option to turn off peer-to-peer mode to prevent any use of mDNS for strict customer security policies.

*Why not PASSing today:* Admin configurability — verified via vendor attestation

---

**`SEC-10.2-2`** §10.2 (SHALL)

> api_proto of the Registry DNS-SD record shall be “https”

*Why not PASSing today:* api_proto=https in the registry's DNS-SD TXT record — the validator does not exercise mDNS / DNS-SD; vendor attests that the registry advertisement is correct

---

**`SEC-12.6-1`** §12.6 (SHALL)

> Default: Vendor certificates or None (shall be configured in order to enable related configurations)

*Why not PASSing today:* Factory-default value for the TLS Server Certificate ("Vendor certificates or None") — manufacturer attestation

---

**`SEC-12.7-1`** §12.7 (SHALL)

> Shall support at least two CTCA for each type of access in order to allow certificate re-provisioning.

*Why not PASSing today:* Admin capacity guarantee (multi-CA / multi-CRL) — attestation

---

**`SEC-12.9-1`** §12.9 (SHALL)

> Default: Vendor certificates or None (shall be configured in order to enable related configurations)

*Why not PASSing today:* Factory-default value for the TLS Client Certificate — manufacturer attestation

---

**`SEC-12.10-1`** §12.10 (SHALL)

> Default: Vendor Root CA(s) or None (shall be configured in order to enable related configurations)

*Why not PASSing today:* Factory-default value for the Node-endpoints Server Trusted CA(s) — manufacturer attestation

---

**`SEC-12.12-1`** §12.12 (SHALL)

> Default: Vendor Root CA(s) or None (shall be configured in order to enable related configurations)

*Why not PASSing today:* Factory-default value for the Control-endpoints Server Trusted CA(s) — manufacturer attestation

---

**`SEC-12.14-1`** §12.14 (SHALL)

> The device shall provide a means to update trust material such that a valid existing trust configuration remains usable until a new configuration has been successfully validated.

*Why not PASSing today:* Admin lifecycle / retrieval surface — verified via vendor attestation

---

**`SEC-12.14-3`** §12.14 (SHALL)

> Existing sessions shall continue with the configuration that was in effect when the session was established until they can safely be terminated.

*Why not PASSing today:* Existing sessions continue with the configuration in effect at session start when admin reconfigures — requires runtime admin-config change + existing-session observation; admin/lifecycle territory

---

**`SEC-12.14-5`** §12.14 (SHALL)

> Private keys are out of scope for retrievable configuration and shall be write-only and shall not be retrievable.

*Why not PASSing today:* Private-key non-retrievability — attestation

---

**`SEC-12.14-8`** §12.14 (SHALL)

> When using the PEM format the transfer channel shall be secure.

*Why not PASSing today:* Operator-side transfer-channel security — attestation

---

**`SEC-12.14-9`** §12.14 (SHALL)

> When using the PKCS#12 format the transfer of the password shall be secure.

*Why not PASSing today:* Operator-side password-transfer security — attestation

---

**`SEC-14.3.1-1`** §14.3.1 (SHALL)

> The Node estimation of the true time shall be within 30 minutes of the true NTP / PTP time used by the OAuth 2.0 Authorization Server.

*Why not PASSing today:* Node estimation within 30 min of true NTP/PTP — requires controlled DUT clock skew; partial wire via expired-token test

---

**`SEC-14.3.1-2`** §14.3.1 (SHALL)

> The estimated time used by the Node to validate the claims of a token shall comply with this requirement.

*Why not PASSing today:* Token-validation clock alignment — same as above

---

**`SEC-14.3.1-3`** §14.3.1 (SHALL)

> The estimated time used by the Node to schedule the fetch / update of the OAuth 2.0 Authorization Server public keys shall comply with this requirement.

*Why not PASSing today:* Key-fetch clock alignment — same as above

---

**`SEC-14.3.2-10`** §14.3.2 (SHALL)

> All the accessible OAuth 2.0 Authorization Servers shall publish the same set of Public Keys such that any OAuth 2.0 Authorization Server may be used by an NMOS Node to obtain the Public Keys and validate access tokens.

*Why not PASSing today:* Multi-AS deployment consistency — same as 14.3.2-9; vendor / deployment attestation

---

**`SEC-14.3.2-4`** §14.3.2 (SHALL)

> An NMOS Node shall invalidate the Public Keys from a previous fetch / update operation 36 hours after obtaining them.

*Why not PASSing today:* 36h hard JWKS invalidation window — vendor attestation. Compressed-clock fixture was sketched (fake AS Cache-Control: max-age=0 + clock-source mock) but not wired; attest via manufacturer sign-off citing nmos/oauth2/tests/test_jwks_cache.py

---

**`SEC-14.3.2-7`** §14.3.2 (SHALL)

> An NMOS Node shall log an event if it invalidates the Public Keys and it should log an event when it gets a set of Public Keys.

*Why not PASSing today:* Log event on invalidation — requires DUT log-stream observation. Vendor attestation.

---

**`SEC-14.3.2-8`** §14.3.2 (SHALL)

> An NMOS Node shall discover through DNS-SD the OAuth 2.0 Authorization Servers URL from the standard IS-10 _nmos-auth._tcp service or it may be configured with a list of URLs.

*Why not PASSing today:* DNS-SD `_nmos-auth._tcp` discovery of the AS URL — the validator does not exercise mDNS / DNS-SD. The spec allows the configured-URL alternative; vendor attests the DNS-SD branch works when the AS is discovered that way

---

**`SEC-14.3.3.4-46`** §14.3.3.4 (SHOULD)

> An NMOS Node should increment a status counter a) when a ReadOnly access is denied: a.1) based on the sub claim, a.2) based on the aud claim, a.3) based on the scope claim, a.4) based on the x-nmos-* claim, b) when a ReadWrite access is denied: b.1) based on the sub claim, b.2) based on the aud claim, b.3) based on the scope claim, b.4) based on the x-nmos-* claim, c) when an access without an Access Token is performed, d) when an access with an invalid or corrupted token is performed, e) when an access with an expired or not-yet-valid token is performed, f) when a TLS client certificate validation fails, g) when a TLS server certificate validation fails during a client access, h) when a fetch/update of the OAuth 2.0 Authorization Server public keys fails, i) when an access is denied because no valid Public Keys are available.

*Why not PASSing today:* Audit status counters — vendor attestation; compare device's post-run counter values against the predicted deltas in this manifest

---

**`SEC-14.3.3.4-47`** §14.3.3.4 (SHALL)

> The status counters shall be 64-bit unsigned integers and shall be monotonic (non-decreasing) since boot/reset/restart.

*Why not PASSing today:* 64-bit monotonic audit counters — vendor attestation

---

**`SEC-14.3.3.4-48`** §14.3.3.4 (SHALL)

> An IPMX device may persist the counters across boot/reset/restart and if so shall provide an administrator a means to reset them through an explicit administrative action.

*Why not PASSing today:* Persisted-counter reset requires admin action — attestation

---

**`SEC-14.3.3.6-4`** §14.3.3.6 (SHALL)

> Wildcards shall not be considered a match.

*Why not PASSing today:* Wildcards not matched for binding — vendor attestation. Wire-testing requires minting a wildcard-SAN client cert (e.g. CN=*.example.com) chained to the trust anchor. Operators understandably prefer not to mint wildcard certs they would not use in production, so this SHALL falls to the manifest: vendor confirms Node refuses to match a token client_id against a wildcard SAN entry

---

**`SEC-14.3.3.6-5`** §14.3.3.6 (SHALL)

> If a wildcard is present in any SAN entry the Node shall treat it as non-matching for the purpose of this check.

*Why not PASSing today:* Wildcard SAN treated as non-matching — vendor attestation; same wire-test constraint as SEC-14.3.3.6-4 (wildcard-SAN cert needed). The two SHALLs restate the same rule

---

**`SEC-14.3.3.7-3`** §14.3.3.7 (SHALL)

> Subscribing to notification messages shall be considered a read-only operation.

*Why not PASSing today:* Classification statement (not a separate Node behaviour): 'Subscribing to notification messages shall be considered a read-only operation.' The underlying access-control logic is already covered by our read-only-token probes; the spec is just defining how to bucket the WS subscribe op for the purposes of the §14.3.3.4 read/write evaluation. Vendor attests that its WS subscribe handler is classified as read-only in the token-validation pipeline.

---

## [LONG-WINDOW] — Long-window timing (hours/days)

**1 entries** (0 SHALL + 1 SHOULD)

Requirements with timing windows in the hours-to-days range. Equivalent unit tests in nmos-reference exercise the logic with a mocked clock.

| ID | § | Level | Spec text |
|---|---|---|---|
| `SEC-14.3.2-6` | §14.3.2 | SHOULD | An NMOS Node should use an exponential backoff, from 1 to 64 seconds, when retrying a fetch / update operation. |

### Detail

**`SEC-14.3.2-6`** §14.3.2 (SHOULD)

> An NMOS Node should use an exponential backoff, from 1 to 64 seconds, when retrying a fetch / update operation.

*Why not PASSing today:* Exponential backoff 1–64s — multi-failure observation; verified by nmos/oauth2/tests/test_jwks_cache.py

---

## [META] — Spec scaffolding / about other party

**22 entries** (16 SHALL + 6 SHOULD)

Not testable as a Node behaviour — spec scaffolding (RFC 2119 vocabulary), precedence rules, requirements ON THE AS / controller / Operator, or feature-gated SHOULDs that resolve to OPTIONAL-ABSENT when the operator does not declare the optional feature.

| ID | § | Level | Spec text |
|---|---|---|---|
| `SEC-4-1` | §4 | SHALL | Normative text describes elements of the design that are indispensable or contain the conformance language keywords: "shall," "should," or "may." |
| `SEC-4-2` | §4 | SHALL | The keywords "shall" and "shall not" indicate requirements strictly to be followed to conform to the document and from which no deviation is permitted. |
| `SEC-4-3` | §4 | SHOULD | The keywords "should" and "should not" indicate that, among several possibilities, one is recommended as particularly suitable, without mentioning or excluding others; or that a certain course of action is preferred b… |
| `SEC-4-4` | §4 | SHALL | The keyword “reserved” indicates a provision that is not defined at this time, shall not be used, and may be defined in the future. |
| `SEC-4-5` | §4 | SHALL | A conformant implementation according to this document is one that includes all mandatory provisions ("shall") and, if implemented, all recommended provisions ("should") as described. |
| `SEC-4-6` | §4 | SHALL | Unless otherwise specified, the order of precedence of the types of normative information in this document shall be as follows: Normative prose shall be the authoritative definition; Tables shall be next; followed by … |
| `SEC-7-1` | §7 | SHALL | Where any requirement in this Technical Recommendation conflicts with a requirement in AMWA IS-10 or AMWA BCP-003-01, the requirement in this Technical Recommendation shall take precedence for any IPMX implementation … |
| `SEC-8-1` | §8 | SHALL | An IPMX device shall comply with this Technical Recommendation. |
| `SEC-9.1-1` | §9.1 | SHALL | In that specific case, the protocol is HTTP without TLS, and the device shall not claim compliance with this Technical Recommendation while so configured. |
| `SEC-9.1-2` | §9.1 | SHALL | Unrestricted read access shall be permitted to all clients. |
| `SEC-9.1-3` | §9.1 | SHALL | Unrestricted write access shall be permitted to all clients. |
| `SEC-13.1-1` | §13.1 | SHALL | An implementation supporting the OAuth 2.0 authorization scheme shall comply with AMWA/NMOS IS-10 and AMWA BCP-003-02 except where this Technical Recommendation specifies otherwise. |
| `SEC-14.3.3.1-1` | §14.3.3.1 | SHALL | An OAuth 2.0 Bearer token shall have a minimum expiration time (exp claim) of 1 hour and a maximum of 24 hours from its creation time (iat claim). |
| `SEC-14.3.3.3-1` | §14.3.3.3 | SHALL | NMOS Controllers and similar NMOS sub-systems shall obtain Bearer tokens to access the APIs of NMOS Nodes. |
| `SEC-14.3.3.3-2` | §14.3.3.3 | SHOULD | NMOS Controllers and similar NMOS sub-systems should obtain Bearer tokens with client_credentials grants to access the APIs of NMOS Nodes. |
| `SEC-14.3.3.4-9` | §14.3.3.4 | SHOULD | Authorizations should be delivered to OAuth 2.0 Clients for specific NMOS Nodes based on their serial number, as defined in the BCP-002-02 Instance Identifier. |
| `SEC-14.3.3.6-10` | §14.3.3.6 | SHOULD | An OAuth 2.0 Authorization Server should enforce this requirement at client registration time and/or when issuing access tokens. |
| `SEC-14.3.3.6-8` | §14.3.3.6 | SHALL | When mTLS is used, OAuth 2.0 clients (Controllers or tools) shall be provisioned such that their client_id value matches (case-insensitively) the CN name or one of the alternates DNS names of their TLS client certific… |
| `SEC-14.3.3.6-9` | §14.3.3.6 | SHALL | Wildcards shall not be used for this purpose. |
| `SEC-14.3.3.7-1` | §14.3.3.7 | SHOULD | An NMOS Node should provide endpoints for getting a WebSocket upgrade that are specific for ReadOnly access and ReadWrite access. |
| `SEC-14.3.3.7-2` | §14.3.3.7 | SHOULD | The ReadOnly endpoint should have the “Guest” suffix. |
| `SEC-14.3.3.7-4` | §14.3.3.7 | SHALL | This shall not be considered as causing side-effects on the state of the NMOS Node. |

### Detail

**`SEC-4-1`** §4 (SHALL)

> Normative text describes elements of the design that are indispensable or contain the conformance language keywords: "shall," "should," or "may."

*Why not PASSing today:* RFC 2119 conformance vocabulary (§4) — meta-spec, not a device behaviour

---

**`SEC-4-2`** §4 (SHALL)

> The keywords "shall" and "shall not" indicate requirements strictly to be followed to conform to the document and from which no deviation is permitted.

*Why not PASSing today:* RFC 2119 conformance vocabulary (§4) — meta-spec, not a device behaviour

---

**`SEC-4-3`** §4 (SHOULD)

> The keywords "should" and "should not" indicate that, among several possibilities, one is recommended as particularly suitable, without mentioning or excluding others; or that a certain course of action is preferred but not necessarily required; or that (in the negative form) a certain possibility or course of action is deprecated but not prohibited.

*Why not PASSing today:* RFC 2119 conformance vocabulary (§4) — meta-spec, not a device behaviour

---

**`SEC-4-4`** §4 (SHALL)

> The keyword “reserved” indicates a provision that is not defined at this time, shall not be used, and may be defined in the future.

*Why not PASSing today:* RFC 2119 conformance vocabulary (§4) — meta-spec, not a device behaviour

---

**`SEC-4-5`** §4 (SHALL)

> A conformant implementation according to this document is one that includes all mandatory provisions ("shall") and, if implemented, all recommended provisions ("should") as described.

*Why not PASSing today:* RFC 2119 conformance vocabulary (§4) — meta-spec, not a device behaviour

---

**`SEC-4-6`** §4 (SHALL)

> Unless otherwise specified, the order of precedence of the types of normative information in this document shall be as follows: Normative prose shall be the authoritative definition; Tables shall be next; followed by formal languages; then figures; and then any other language forms.

*Why not PASSing today:* RFC 2119 conformance vocabulary (§4) — meta-spec, not a device behaviour

---

**`SEC-7-1`** §7 (SHALL)

> Where any requirement in this Technical Recommendation conflicts with a requirement in AMWA IS-10 or AMWA BCP-003-01, the requirement in this Technical Recommendation shall take precedence for any IPMX implementation claiming compliance with this Technical Recommendation.

*Why not PASSing today:* Spec-precedence rule — meta, not a device behaviour

---

**`SEC-8-1`** §8 (SHALL)

> An IPMX device shall comply with this Technical Recommendation.

*Why not PASSing today:* Generic compliance statement ('IPMX device shall comply with this TR') — meta-spec

---

**`SEC-9.1-1`** §9.1 (SHALL)

> In that specific case, the protocol is HTTP without TLS, and the device shall not claim compliance with this Technical Recommendation while so configured.

*Why not PASSing today:* Self-disqualifying: device 'shall not claim compliance' under NAP=0 — not a testable behaviour against a certified DUT

---

**`SEC-9.1-2`** §9.1 (SHALL)

> Unrestricted read access shall be permitted to all clients.

*Why not PASSing today:* Same — describes NAP=0 (non-compliant) read access

---

**`SEC-9.1-3`** §9.1 (SHALL)

> Unrestricted write access shall be permitted to all clients.

*Why not PASSing today:* Same — describes NAP=0 (non-compliant) write access

---

**`SEC-13.1-1`** §13.1 (SHALL)

> An implementation supporting the OAuth 2.0 authorization scheme shall comply with AMWA/NMOS IS-10 and AMWA BCP-003-02 except where this Technical Recommendation specifies otherwise.

*Why not PASSing today:* Generic 'implementation supporting OAuth 2.0 shall comply with IS-10 + BCP-003-02' — meta-spec

---

**`SEC-14.3.3.1-1`** §14.3.3.1 (SHALL)

> An OAuth 2.0 Bearer token shall have a minimum expiration time (exp claim) of 1 hour and a maximum of 24 hours from its creation time (iat claim).

*Why not PASSing today:* Token lifetime [1h, 24h] applies to token issuance — the spec's §14.3.3.4 validation pseudocode only checks exp > now(); enforcing the upper/lower bound is the AS's responsibility, not the Node's

---

**`SEC-14.3.3.3-1`** §14.3.3.3 (SHALL)

> NMOS Controllers and similar NMOS sub-systems shall obtain Bearer tokens to access the APIs of NMOS Nodes.

*Why not PASSing today:* Requirement on Controller behaviour, not the Node under test — meta

---

**`SEC-14.3.3.3-2`** §14.3.3.3 (SHOULD)

> NMOS Controllers and similar NMOS sub-systems should obtain Bearer tokens with client_credentials grants to access the APIs of NMOS Nodes.

*Why not PASSing today:* Requirement on Controller behaviour, not the Node under test — meta

---

**`SEC-14.3.3.4-9`** §14.3.3.4 (SHOULD)

> Authorizations should be delivered to OAuth 2.0 Clients for specific NMOS Nodes based on their serial number, as defined in the BCP-002-02 Instance Identifier.

*Why not PASSing today:* Recommended authorization scoping to serial number — informative best practice for the AS, not directly testable on the Node

---

**`SEC-14.3.3.6-10`** §14.3.3.6 (SHOULD)

> An OAuth 2.0 Authorization Server should enforce this requirement at client registration time and/or when issuing access tokens.

*Why not PASSing today:* Requirement on Authorization-Server or OAuth client side, not Node — meta

---

**`SEC-14.3.3.6-8`** §14.3.3.6 (SHALL)

> When mTLS is used, OAuth 2.0 clients (Controllers or tools) shall be provisioned such that their client_id value matches (case-insensitively) the CN name or one of the alternates DNS names of their TLS client certificate.

*Why not PASSing today:* Client provisioning rule: OAuth 2.0 clients shall be provisioned such that client_id matches the cert CN/SAN — applies to the AS at client-registration time, not the Node

---

**`SEC-14.3.3.6-9`** §14.3.3.6 (SHALL)

> Wildcards shall not be used for this purpose.

*Why not PASSing today:* Wildcards shall not be used in OAuth client provisioning — applies to the AS / client-registration tooling, not the Node

---

**`SEC-14.3.3.7-1`** §14.3.3.7 (SHOULD)

> An NMOS Node should provide endpoints for getting a WebSocket upgrade that are specific for ReadOnly access and ReadWrite access.

*Why not PASSing today:* Feature-gated SHOULD — exercised only when --supports guest-ws is declared. Default behaviour: OPTIONAL-ABSENT (device does not claim the optional feature). When claimed and the device fails, this becomes a real REF-NODE GAP.

---

**`SEC-14.3.3.7-2`** §14.3.3.7 (SHOULD)

> The ReadOnly endpoint should have the “Guest” suffix.

*Why not PASSing today:* Feature-gated SHOULD — same as SEC-14.3.3.7-1; OPTIONAL-ABSENT unless --supports guest-ws is declared.

---

**`SEC-14.3.3.7-4`** §14.3.3.7 (SHALL)

> This shall not be considered as causing side-effects on the state of the NMOS Node.

*Why not PASSing today:* Informative: connection-state side-effects not considered Node side-effects

---

## [REF-NODE GAP] — Reference-node feature missing

**1 entries** (1 SHALL + 0 SHOULD)

Testable in principle once reference-node grows the feature.

| ID | § | Level | Spec text |
|---|---|---|---|
| `SEC-12.14-2` | §12.14 | SHALL | When an administrator changes the security policy configuration (e.g., NAP, RAP, RAAM, OAIM, TCT) or updates trust material (CAs, CRLs, certificates), new connections shall follow the new configuration immediately. |

### Detail

**`SEC-12.14-2`** §12.14 (SHALL)

> When an administrator changes the security policy configuration (e.g., NAP, RAP, RAAM, OAIM, TCT) or updates trust material (CAs, CRLs, certificates), new connections shall follow the new configuration immediately.

*Why not PASSing today:* CRL behaviour — reference-node does not implement CRL handling

---

