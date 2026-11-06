# poseidon-rust, trimmed

The Kohaku SDK's `poseidon-rust` (ZKNoxHQ/kohaku-rs `crates/poseidon-rust` at 7043d3b, itself from
[TaceoLabs/poseidon-rust](https://github.com/TaceoLabs/poseidon-rust)), patched into the signer's build in
place of the original: `kohaku-crypto` is unchanged and calls this one.

The only change: it keeps the circom parameters for widths t2..t6 (1 to 5 inputs) and drops t7..t14. The
signer hashes 1 input (nullifying key), 3 (master public key) and 5 (Poseidon-EdDSA challenge); the other
tables took 236 KiB, and the image didn't fit the dabao's 873 KiB application region. More inputs return
`UnsupportedInputLength`. The test module of `poseidon.rs` is removed (its random tests need `ark-std`);
the signer's tests check the hashes through the Railgun engine's address vectors.
