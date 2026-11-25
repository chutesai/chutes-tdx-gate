# Wire specification for Chutes TDX VM endpoints

This is the normative specification of what a bring-your-own Intel TDX VM endpoint serves and how
Chutes checks it: `/attest` and REPORTDATA (4.1), the signed measurement document (4.2), E2E v2
inside the VM (4.3) and `/health` (4.4). The code and the other kit repositories cite these
section numbers.

`vectors/` holds the test vectors the gate consumes: `e2e_v2.json`, `reportdata.json` and
`health.json`, with `mlkem768.py` (the pure-Python ML-KEM-768 that `../sealcheck/open.py` uses to
open the gate's sealed answers). `vectors/SHA256SUMS` lists their sha256. Both forms of the gate
pass every case (`make test`, `make pytest`). The vectors for section 4.2 (`measurements.json`,
`rtmr0_template.json`) and `quote.json` are in `chutesai/chutes-tdx-measure`, under `spec/vectors/`.

Where the gate is deliberately stricter than the text below, `../crosstest/differential.py` lists
the cases.

`strict_json/numbers.json` is this repository's own test set (it is not in `vectors/`): the numbers
both forms' strict JSON readers must accept or refuse alike. A number that a float64 reads as
infinity is refused however it is written, an integer without a fraction or an exponent included.
The Go reader's tests (`go test ./pkg/sjson`, part of `make test`) and the Python library's
(`make pytest`) read that one file.

---

## 4. Wire formats

The vectors fix every format below byte for byte.

### 4.1 `/attest` and REPORTDATA

**Request:** `GET /attest?nonce=<64 lower-case hex>` on the endpoint port, exactly one query parameter. Any other query
(upper case, other lengths, a repeated `nonce`, another parameter) is refused by the gate with 400
`{"detail":{"code":"attest_bad_nonce"}}`; a method other than GET with 405.

**Answer:** `200`, `Content-Type: application/json`, the body exactly `compact({"quote": B64(quote), "public_key":
B64(ek)})`, keys in that order, nothing else.

```
REPORTDATA (64 bytes) = SHA-512( "chutes-tdx-endpoint-attest-v1" || 0x00 || nonce (32 bytes) || public_key (1184 bytes) )
```

- `nonce` is the 32 bytes the hex names; `public_key` the raw 1184-byte ML-KEM-768 encapsulation key (not its base64).
- **The key:** one ML-KEM-768 key pair per boot, generated inside the VM by the gate when it starts, kept in memory only,
  the same for every `/attest` and every request of that boot.
- **The quote:** configfs-tsm, serialized in the gate (one at a time): `mkdir /sys/kernel/config/tsm/report/<unique>`;
  read `provider` (must be `tdx_guest`) and `generation`; write the 64 REPORTDATA bytes to `inblob`; read `outblob`;
  read `generation` again: it must be the first value plus 1 (another writer interleaved otherwise: retry once, then
  503 `{"detail":{"code":"attest_busy"}}`); `rmdir`. The quote is a TDX quote v4 (version 4, TEE type 0x81) of at most
  32,768 bytes.
- **Domain separation (MUST).** No route of the VM returns a quote over caller-chosen REPORTDATA, and no code in the VM
  computes REPORTDATA as SHA-512 of a byte string starting with `chutes-tdx-endpoint-attest-v1` 0x00 except this route.
  A quote the VM makes for its own key service uses the owner's own tag (the reference in `chutesai/chutes-tdx-image`
  uses `chutes-tdx-image-keyrelease-ref-v1`).
- **Quote version:** v4 only. A future quote version (Google moving to v5 quotes) is refused everywhere, fail closed,
  until this specification changes. When every VM fails the `quote` check, the quote version is the first thing to check.
- **Reader rules** (the validator's evidence relay and controller, and the client): the body at most 65,536 bytes;
  JSON with no duplicate key; an object with exactly `quote` and `public_key`; both `B64`; `quote` decodes to 1..32,768
  bytes and `public_key` to exactly 1184 bytes. Anything else: `vm_attest_invalid` (validator) or
  `endpoint_vm_attest_invalid` (client). The validator's request has a 10 s total deadline.

REPORTDATA is a single SHA-512 so that it is simple to implement; the domain-separation rule is what keeps a quote over
caller-chosen REPORTDATA off every route. Vectors: `reportdata.json` (cases, the wrong forms that must not verify, the
refused queries and answers), `quote.json` (the TD body offsets).

### 4.2 The signed measurement document

**Format** `chutes.tdx-measurements.v1`, verified in this order (`chutes-tdx-measure verify-document` implements it):

1. **Size:** 1..65,536 bytes, else `document_too_large` (checked before anything else).
2. **Signature:** `signature_b64` is `B64` of exactly 64 bytes, with no whitespace; Ed25519 (RFC 8032, as
   `cryptography`'s `Ed25519PublicKey.verify`) over **the exact bytes of the document**, under the 32-byte raw public
   key. Else `document_signature_invalid`. Nothing is parsed before this passes.
3. **Parse:** strict UTF-8 without a byte-order mark; JSON (RFC 8259) with no duplicate key at any level and no `NaN` or
   `Infinity`; a top-level object with exactly `type`, `image_sha256`, `accept`. Else `document_invalid`.
4. **Fields:** `type` = `chutes.tdx-measurements.v1`; `image_sha256` `HEX64`; `accept` a list of 1..32 entries, each
   exactly one of:
   - **exact:** `{"machine_type", "mrtd", "rtmr0", "rtmr1", "rtmr2", "rtmr3"}`, `mrtd`/`rtmr0`/`rtmr1`/`rtmr2` `HEX96`,
     `rtmr3` `HEX96` or `null`;
   - **firmware-following:** `{"machine_type", "mrtd", "rtmr0_template", "rtmr1", "rtmr2", "rtmr3"}`, `mrtd` exactly
     `"gce-endorsed"`, `rtmr0_template` exactly `{"before_cfv": HEX96, "after_cfv": [1..32 × HEX96]}`, `rtmr1`/`rtmr2`
     `HEX96`, `rtmr3` `HEX96` or `null`;

   `machine_type` `MACHINE_TYPE`. Else `document_invalid`. (`rtmr3` is always present: `null` means "not checked".)
5. **The image:** `image_sha256` equals the image's `archive_sha256` (validator) or the trust file's `vm.image_sha256`
   (client). Else `document_image_mismatch`.

**Signing.** The tools are `chutes-tdx-measure sign` or `chutes tdx sign` (the Chutes client); OpenSSL 3 also works:
`openssl pkeyutl -sign -rawin -inkey key.pem -in m.json | base64 -w0`. The public key is registered as `B64` of its
32 raw bytes; its fingerprint is SHA-256 of those 32 bytes, lower hex. The key is used for nothing else; domain separation
is the document's `type` plus that rule.

**Matching** a quote's registers (lower-cased) on an endpoint of machine type M, in this order (the floor applies to
every form):
1. Documents that fail steps 1–5 are skipped (and named); **none valid**: `measurements_unsigned`.
2. **The MRTD must be admitted** (below), whatever the form; otherwise `firmware_refused`. A TDVF build Chutes denies
   or that is below the floor is refused even under an exact entry; the TDX module's own level is the quote row's TCB
   status (dcap).
3. Documents in listing order (validator: `created_at` order), entries in document order, only entries whose
   `machine_type` is M; the first entry that matches wins:
   - `rtmr1` and `rtmr2` equal; `rtmr3` equal unless `null`;
   - **exact:** `mrtd` and `rtmr0` equal;
   - **firmware-following:** for at least one admitted build B, `rtmr0` = `fold(rtmr0_template, B.cfv)`, where
     `fold(t, c)`: `r = SHA-384(bytes(t.before_cfv) || bytes(c))`; for each `d` in `t.after_cfv`: `r = SHA-384(r ||
     bytes(d))` (the SDK's `owner_vm_firmware.evaluate_rtmr0_template`; the vectors use lower case, the SDK prints
     upper case).

   No entry matches: `measurements_unmatched`.

**Admission of an MRTD:** a build B is admitted when Google's endorsement of B verifies under the pinned GCE TCB root at
`now`, it lists the MRTD as a RAM-independent entry (`ram_gib` 0, never early-accept), B's binary is indexed (its CFV
derived by `derive_cfv_sha384`), and B clears the floor: `cl_spec` ≥ max(919307640, `min_cl_spec`), `svn` ≥ max(2,
`min_svn`), golden timestamp ≥ 2026-05-21, and B's UEFI digest not in `denied_builds`.
- **The client's floor** is the `firmware_floor` of the platform entry in its saved trust file, over the client's own
  firmware index (`owner_vm_firmware.load_index`, refreshed once from Google's bucket for an unknown MRTD). The client
  reads no current catalog; the saved floor applies.
- **The validator's floor** is the TDX floor and deny list of Chutes' firmware policy, over the validator's firmware
  index (curated and automatically admitted builds), applied to every entry form. The floor in Chutes' signed catalog
  entry is written from the same policy when it is published, so the two agree.

Results: `(document, entry)`, or `measurements_unsigned`, `firmware_refused`, `measurements_unmatched`. The validator
reports any of them as `attest_refused:measurements`; the client as `endpoint_vm_measurements_unsigned`,
`endpoint_vm_firmware_refused`, `endpoint_vm_measurements_unmatched`. Vectors: `measurements.json` (16 document cases,
17 match cases, 4 key proofs), `rtmr0_template.json`.

**What the registers cover on GCP:** MRTD is Google's TDVF; RTMR0 the shape's VMM data, the CFV and UEFI variables an
image can change; RTMR1 the GPT and each EFI application (a UKI's Authenticode covers its kernel, initrd and command
line); RTMR2 what the boot loader measures; RTMR3 runtime extensions only.

### 4.3 E2E v2 inside the VM, and the relay ↔ VM transport

**The wire between the client and the gate is Chutes' E2E v2, unchanged** (the SDK's `cpu_e2e.py` v2 constants and
`endpoint_e2e.py`). For a VM:

| Binding | Value the gate checks against |
|---|---|
| `endpoint_id` | the instance metadata attribute `chutes-endpoint-id` |
| `instance_id` | the instance metadata `instance/id` (decimal); MR_OWNER proves it to the caller |
| `path`, `stream` | the gate's own route table (the endpoint's declared routes) |
| `nonce`, `ts` | its replay cache (65,536 live entries) and its clock: 120 s behind, 60 s ahead |

The gate reads both identity values once at start from `http://169.254.169.254/computeMetadata/v1/` with
`Metadata-Flavor: Google` (retrying until they answer); until then every route answers 503 `e2e_v2_identity_unknown`
(`/attest` works without them).

**The envelope's fields**, the closed set `{v, endpoint_id, instance_id, path, stream, nonce, ts,
e2e_response_pk, body}`, each of exactly this type, else 400 `e2e_v2_malformed`:
- `v`: the JSON integer 2;
- `endpoint_id`, `instance_id`: strings of 1..256 code points, each *printable* in Python's `str.isprintable()` sense:
  no code point of Unicode categories Cc, Cf, Cs, Co, Cn, Zl, Zp, or Zs other than U+0020;
- `path`: the same rule, and it starts with `/`;
- `stream`: a JSON boolean;
- `nonce`: exactly 43 characters of `[A-Za-z0-9_-]`;
- `ts`: a JSON integer (no fraction or exponent) of milliseconds;
- `e2e_response_pk`: standard base64 with padding that decodes to 1184 bytes;
- `body`: a JSON object. **`body.stream`, when present, must be a JSON boolean equal to `stream`**, else 400
  `e2e_v2_stream_mismatch`; absent counts as `false`. The SDK's container runtime compares Python truthiness and
  admits `"stream": 1` on a stream route; a VM gate is stricter, and the SDK client never sends a non-boolean. Vector
  R32 records both results.

**Checks, in this order, before the application sees anything** (`endpoint_e2e.open_request`): open (v2 info and AAD;
else 400 `e2e_v2_undecryptable`); gunzip one member of at most 64 MiB and the closed envelope (400 `e2e_v2_malformed`);
identity known (503 `e2e_v2_identity_unknown`); `endpoint_id` (403 `e2e_v2_wrong_endpoint`); `instance_id` (403
`e2e_v2_wrong_instance`); method POST (405 `e2e_v2_method`); presented path = bound path (403 `e2e_v2_wrong_path`);
`(path, POST, stream)` served (404 `e2e_v2_route_not_served`); body `stream` = bound `stream` (400
`e2e_v2_stream_mismatch`); `ts` not stale (400 `e2e_v2_stale`), not ahead (400 `e2e_v2_from_the_future`); nonce not
admitted (409 `e2e_v2_replayed`); the cache below its bound (503 `e2e_v2_busy` with `Retry-After`); then the nonce is
admitted (consumed last).

**Relay → VM request** (from the validator's internal address), exactly these headers in this order and no other:

```
POST <route path> HTTP/1.1
Host: <internal ip>:8080
Accept-Encoding: identity
Connection: keep-alive
User-Agent: chutes-vms-relay/1
Content-Type: application/octet-stream
X-E2E-Stream: true | false        (the route's declared flag)
Content-Length: <n>
```

No key, no caller identity, no `X-E2E-Encrypted`. The body is the client's v2 blob as received.

**VM → relay answer**, exactly one of three forms:
1. **Sealed (non-stream, or any non-2xx):** HTTP status = the sealed status (200..599), `Content-Type:
   application/json`, body exactly `{"e2e":"<B64 blob>"}`. Blob = `mlkem_ct || nonce || ct || tag` to
   `e2e_response_pk`, info `e2e-resp-v2`, AAD `chutes-e2e-v2 answer` || SHA-256(request blob), plaintext
   gzip(`{"v":2,"status":S}` `\n` body).
2. **Stream (a stream route and a 2xx application status):** `200`, `Content-Type: text/event-stream`, the body exactly
   `data: {"e2e_init":"<B64 mlkem_ct>"}\n\n` then one `data: {"e2e":"<B64 chunk>"}\n\n` per chunk: head (kind 1,
   `{"v":2,"status":S}`), data (kind 2, the application's bytes, at most 65,536 per chunk), and exactly one end (kind 3,
   empty) after the application's body ended normally. Each line at most 1 MiB.
3. **Refusal before or instead of opening:** the status of the table above, `Content-Type: application/json`, body
   exactly the compact bytes `{"detail":{"code":"<code>"}}` with `<code>` **one of the 15 enumerated codes**:
   the 13 of the table above, plus, after a request opened, 502 `e2e_v2_app_failed` (the application failed before a
   complete answer) and 502 `e2e_v2_answer_too_large` (over the gate's cap); both unsealed, with nothing of the
   application in them. `Retry-After` (an integer 1..180) only with 503 `e2e_v2_busy`. The vector `e2e_v2.json`
   `refusal_bodies` holds the 15 exact bodies.

**The relay's handling of a VM's answer:**
- 200 on a non-stream route: read up to the wire cap; the body must be exactly `{"e2e":"<B64>"}`; the blob (at most the
  answer cap) goes to the client as `application/octet-stream`.
- 200 on a stream route: `Content-Type` must be `text/event-stream`; blank lines and the exact `e2e_init` and `e2e`
  event lines pass unchanged, and any other line is dropped. Anything else: 502 `endpoint_upstream_error`.
- Non-200: read up to 64 KiB; `{"e2e":"<B64>"}` → the blob with that status (a sealed error); a body byte-equal to one
  of the 15 enumerated refusal bodies with that code's status → that body (and, only for `e2e_v2_busy`, a numeric
  `Retry-After` of 1..180; dropped otherwise); anything else → 502 `endpoint_upstream_error`, and nothing of the VM's
  body or headers reaches the client. A VM therefore chooses among 15 fixed refusals and nothing more.

**What the gate does with an opened request:**
- forwards `POST http://127.0.0.1:<app port><app path>` with only `Host`, `Content-Type: application/json` and
  `Content-Length`, the body the JSON encoding of `envelope.body`; **nothing is added** (no `stream_options`, no
  identity);
- seals the application's status and body bytes verbatim (form 1), or streams them (form 2); passes **no** application
  header;
- answers 502 `e2e_v2_app_failed` on every route when the application's status is one HTTP sends without a body (1xx,
  204, 304), which cannot carry a sealed answer;
- logs no body, no envelope field and no decrypted byte: only route, status and refusal codes.

**The owner's choices:** this repository's `tdx-gate`, its Python library, or their own code conforming to
`e2e_v2.json`. Vectors: 34 requests (R1–R33 and R15a) evaluated in order against one replay cache (among them the unknown
identity, the field rules and `body.stream` as a JSON boolean), 5 answers, one stream with three broken variants, the 15
refusal bodies and what the relay passes, and the replay-cache bound.

### 4.4 `/health`

- `GET <health path> HTTP/1.1` on port 8080 with exactly `Host: <ip>:8080`, `Accept-Encoding: identity`, `Connection:
  close` and `User-Agent: chutes-vms-controller/1` (the same headers for the controller's and the evidence relay's
  `GET /attest`, there with `User-Agent: chutes-vms-relay/1`), 5 s total, no redirect followed, the body read up to
  4096 bytes and discarded.
- **Healthy:** a status 200..299 with at most 4096 body bytes. Everything else (1xx, 3xx, 4xx, 5xx, a longer body, a
  timeout, a refused connection) is unhealthy. Vectors: `health.json`.
- **The VM answers healthy only once it has its key and can serve.** The first healthy answer closes the key window
  (the VM's only path to its owner's key service). With the gate, `/health` passes through to the application's health
  URL: the gate answers 200 with an empty body if the application answered 2xx within 4 s, else 503.

