# Using your own image

If you build your image without the `chutesai/chutes-tdx-image` template, Chutes needs:

- **The service** on port 8080, implementing `spec/SPEC.md`: `/attest`, E2E v2 and your health
  path. Use `tdx-gate`, or your own implementation tested against `spec/vectors`.
- **A signed measurement document** (spec §4.2), and its Ed25519 key registered with a proof that
  you hold it: the key's signature over the ASCII bytes
  `"chutes-tdx-measurement-key-proof-v1" ‖ 0x00 ‖ user_id ‖ 0x00 ‖ archive_sha256`, where
  `user_id` is your Chutes user id and `archive_sha256` the lower-case hex sha256 of `disk.tar.gz`.
  `chutes-tdx-measure key proof` makes it.
- **The disk image:** `disk.tar.gz`, gzip of a GNU-format tar (sparse is fine) holding exactly one
  member, `disk.raw`, whose size is a whole number of GiB (at most 32). It must boot with UEFI on a
  Google `c3` TDX machine with gVNIC. It runs on Google's own TDX firmware, so MRTD is Google's.
- **Network:** the VM reaches only the metadata server (169.254.169.254) and, until it first
  answers healthy, your key service on port 443 through the relay in the metadata attribute
  `chutes-key-relay`. DNS does not resolve.
- **Limits:** up to 4 VMs per account, and one region per endpoint.
- **What stays readable:** the boot partition (bootloader or UKI, kernel, initrd, command line) is
  readable and measured. Keep secrets on an encrypted partition that your key service unlocks after
  it checks the quote, and protect the readable root's integrity, for example with dm-verity.
