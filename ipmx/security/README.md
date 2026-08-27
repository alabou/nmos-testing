# IPMX Security Certification Test Suite

VSF TR-10-SECURITY compliance validator for IPMX devices.

This subproject is the test tooling VSF uses to certify that an IPMX
device implements the TR-10-SEC control-plane security spec
(TLS, NAP, RAP, RAAM, OAIM, TCT, IS-10 OAuth 2.0). The validator is
run against a running DUT (device under test) — initially our own
`nmos-reference/` implementation, later third-party devices submitted
for certification.

## Test surface

Three certifiable configurations, each producing one validator run:

| `--config` | Description | RAAM | Reference-node script |
| :--- | :--- | :--- | :--- |
| **A** | mTLS without OAuth 2.0 (mandatory) | 0 | `start-node1-noauth2.sh` |
| **B** | OAuth 2.0 with server TLS (mandatory) | 1 | `start-node1-nomtls.sh` |
| **C** | mTLS + OAuth 2.0 (optional) | 2 | `start-node1.sh` |

The validator enforces TR-10-SEC cross-constraints on the CLI:
- `--expect-nap 0` is never accepted — `§9.1` says non-compliant.
- `--expect-nap 1` is only legal with `--config A` — `§9.2` forbids NAP=1 with OAuth 2.0.
- `--expect-oaim` is required with `--config {B, C}` and forbidden with `--config A`.

## Two-stage testing strategy

**Stage 1 — fake AS.** [`ipmx_fake_as.py`](ipmx_fake_as.py) is an
in-process OAuth 2.0 / OIDC authorization server. The validator points
the DUT at it via the launch script's `<as-host> <as-port>` args, then
mints adversarial tokens (`alg=HS256`, `aud=[]`, `exp` in the past,
missing `typ`, etc.) and asserts the DUT rejects them. Real Keycloak
won't emit such tokens — Stage 1 is the only way to exercise the
spec's failure paths.

**Stage 2 — Keycloak.** The existing `keycloak/` deployment emits
production-shaped tokens. [`ipmx_security_scenarios.py`](ipmx_security_scenarios.py)
runs a CSV of access-control scenarios (subject × DUT path × method
→ expected status), fetching real tokens via
`keycloak.test_tokens.get_client_token` / `get_user_token` and
verifying the DUT's access matrix matches what TR-10-SEC §14.3.3.4
mandates.

## Quick start

Every configuration below drives the DUT over TLS by DNS name. The shipped
certificates carry DNS SANs of the form `XYZ-SNX000nn` and no IP SANs, so an
IP literal fails hostname verification (RFC 6125). Add these to `/etc/hosts`
before running anything here:

```
127.0.0.1   XYZ-SNX00000    # OAuth 2.0 Authorization Server (fake AS or Keycloak)
127.0.0.1   XYZ-SNX00001    # device under test
127.0.0.1   XYZ-SNX00002    # second node, for multi-node scenarios
```

### Configuration A (mTLS without OAuth 2.0)

```bash
cd security
python3 ipmx_validate_security.py \
  --launch-dut ../nmos-reference/start-node1-noauth2.sh \
  --launch-dut-wait https://XYZ-SNX00001:7051/x-nmos/node/v1.3/self \
  --dut XYZ-SNX00001:7051 \
  --instance-id XYZ-SNX00001 \
  --config A \
  --expect-nap 2 --expect-rap 0 --expect-tct 0 \
  --client-cert "$IPMX_CERT_ROOT/build.0/pem/ExampleDeviceClient.ABC.SNX00001.chain.pem" \
  --client-key  "$IPMX_CERT_ROOT/build.0/key/ExampleDeviceClient.ABC.SNX00001.key" \
  --attestation-manifest /tmp/attest-configA.md \
  --json-out /tmp/results-configA.json
```

Expect `SHALL 27/27 testable passed, 0 failed`.

### Configuration B (OAuth 2.0 + server TLS), Stage 1

```bash
python3 ipmx_validate_security.py \
  --launch-dut ../nmos-reference/start-node1-nomtls.sh \
  --launch-dut-wait https://XYZ-SNX00001:7051/x-nmos/node/v1.3/self \
  --dut XYZ-SNX00001:7051 \
  --instance-id XYZ-SNX00001 \
  --config B \
  --expect-rap 0 --expect-oaim 0 --expect-tct 0 \
  --fake-as --fake-as-host XYZ-SNX00000 --fake-as-port 9443 \
  --attestation-manifest /tmp/attest-configB-stage1.md
```

Expect `SHALL 101/101 testable passed, 0 failed`. `--expect-rap 0` because
`start-node1-nomtls.sh` hardcodes `RAP=0` — see *Getting the invocation
right* below.

### Configuration C (mTLS + OAuth 2.0), Stage 1

```bash
python3 ipmx_validate_security.py \
  --launch-dut ../nmos-reference/start-node1.sh \
  --launch-dut-wait https://XYZ-SNX00001:7051/x-nmos/node/v1.3/self \
  --dut XYZ-SNX00001:7051 \
  --instance-id XYZ-SNX00001 \
  --config C \
  --expect-rap 0 --expect-oaim 0 --expect-tct 0 \
  --client-cert "$IPMX_CERT_ROOT/build.0/pem/ExampleDeviceClient.ABC.SNX00001.chain.pem" \
  --client-key  "$IPMX_CERT_ROOT/build.0/key/ExampleDeviceClient.ABC.SNX00001.key" \
  --fake-as --fake-as-host XYZ-SNX00000 --fake-as-port 9443 \
  --attestation-manifest /tmp/attest-configC-stage1.md
```

Expect `SHALL 106/106 testable passed, 0 failed`. Every token probe runs
twice, reported as `[cc]` (client_credentials) and `[ac]`
(authorization_code), so both grant shapes are exercised.

### Configuration C, Stage 2 (Keycloak)

```bash
# Pre-start and provision Keycloak first:
(cd ../keycloak && ./start-keycloak.sh)
(cd ../keycloak && ./start-init-keycloak.sh)

python3 ipmx_validate_security.py \
  --launch-dut ../nmos-reference/start-node1.sh \
  --launch-dut-wait https://XYZ-SNX00001:7051/x-nmos/node/v1.3/self \
  --dut XYZ-SNX00001:7051 \
  --instance-id XYZ-SNX00001 \
  --config C \
  --expect-rap 0 --expect-oaim 0 --expect-tct 0 \
  --client-cert "$IPMX_CERT_ROOT/build.0/pem/ExampleDeviceClient.ABC.SNX00000.chain.pem" \
  --client-key  "$IPMX_CERT_ROOT/build.0/key/ExampleDeviceClient.ABC.SNX00000.key" \
  --no-fake-as \
  --keycloak-url https://XYZ-SNX00000:9443 --keycloak-realm TR-10-SEC \
  --attestation-manifest /tmp/attest-configC-stage2.md
```

Expect `SHALL 28/28 testable passed, 0 failed`. Far fewer requirements are
testable than in Stage 1 because a live Keycloak refuses to mint the
malformed tokens the adversarial probes need — that is the whole reason
Stage 1 exists.

## Getting the invocation right

Four things silently produce a wrong or failed run. All four cost real
debugging time; none of them is a fault in the validator or the DUT.

**Match `--expect-rap` to what the launch script actually does.** The
validator passes only `<as-host> <as-port>` to `--launch-dut`; it does *not*
forward `--rap=`. `start-node1.sh` and `start-node1-nomtls.sh` both hardcode
`RAP=0`, so `--expect-rap 2` fails four SHALLs with `DUT advertises RAP=0;
expected 2` — an operator-declaration mismatch, not a device fault.

**Configs A and C need `--client-cert` / `--client-key`.** Those
configurations require a client certificate at the TLS layer, so an
anonymous readiness probe fails during the handshake and the run aborts with
`DUT did not become reachable within 30.0s` — which reads like a dead node
rather than a missing flag.

**Stage 2 needs the `SNX00000` client certificate, not `SNX00001`.** Under
mTLS the validator derives `client_id` from the client cert's SAN to satisfy
the §14.3.3.6 client_id/cert binding, then asks Keycloak for a
`client_credentials` token under that name. `…ABC.SNX00001.example.com`
matches the `controller-SNX00001` subject in the grants CSV and is therefore
provisioned as the Controller's **authorization-code** client, with no
service account — Keycloak answers `Client not enabled to retrieve service
account`. `…ABC.SNX00000.example.com` has one. Stage 1 is unaffected: the
fake AS mints its own tokens.

**Read the WARNING lines, not just the failure list.** When token
acquisition fails, the validator logs the cause once as a `WARNING` and then
reports the *consequence* on every affected requirement — typically 17
failures all saying `DUT advertises <TAG>=None`. The tag really is missing
from the response, but only because `/self` returned 401, which happened
because no token could be obtained. Grepping the log for `WARNING` finds the
real cause in one step; reasoning from the failure list points at the Node.

## Files

| File | Role |
| :--- | :--- |
| `ipmx_validate_security.py` | Main CLI / requirement registry / per-section checks |
| `ipmx_security_common.py` | `Requirement`, `RequirementResult`, `untestable`, registry, report formatting |
| `ipmx_security_tokens.py` | JWT minting with arbitrary claim/header mutation; JWKS export |
| `ipmx_security_probes.py` | TLS handshake probe, HTTP request, WS upgrade |
| `ipmx_fake_as.py` | Stage 1 in-process OAuth 2.0 AS (RFC 8414 + OIDC Discovery + JWKS) |
| `ipmx_security_scenarios.py` | Stage 2 CSV runner; imports `keycloak/` directly |
| `ipmx_security_cases.csv` | Stage 2 scenarios seed |
| `requirements.txt` | Runtime dependencies (inherits `keycloak/requirements.txt`) |

## Dependencies

```bash
pip install -r requirements.txt
```

Inherits from `../keycloak/requirements.txt`. Adds `aiohttp` for the
fake AS and outbound probes, and `cryptography` for X.509 + JWT signing.

## Attestation manifest

Requirements that cannot be probed over the wire (admin-UI
configurability, CRL workflow, write-only key storage, etc.) appear in
the report as `CANNOT-TEST` and are written to a Markdown manifest the
VSF auditor signs off out-of-band. The manifest path is given via
`--attestation-manifest <path>` and a JSON-shaped equivalent goes to
`--json-out <path>`.

## Cross-subproject coupling

The validator imports from `keycloak/` (provisioning + token fetch).
That's the only cross-subproject Python dependency — by design, since
`keycloak/` is the workspace's home for OAuth 2.0 infrastructure and
duplicating its logic would create drift. Everything else (streams/,
nmos-reference/, usb/) is invoked only as subprocess where needed
(e.g. the DUT launch script).
