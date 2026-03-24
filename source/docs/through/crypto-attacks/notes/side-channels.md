# Side-channel attacks

If you want to break crypto today, the usual approach is not to attack the mathematics.
You attack the implementation. A correctly implemented AES-256 has no known practical
attack. The AES-256 running on a microcontroller that leaks key bits through its power
consumption is a different matter.

Side-channel attacks extract information from the physical or computational behaviour of
a device rather than from the ciphertext itself. The algorithm is correct; the execution
environment leaks.

## Power analysis

Every cryptographic operation consumes electricity. The amount varies with the data being
processed. A conditional branch that takes different paths for a 0 bit and a 1 bit draws
slightly different current. An attacker with a current probe and an oscilloscope can
observe these differences.

Simple Power Analysis (SPA) reads a single power trace and extracts key material directly.
It works against naive implementations where key-dependent operations are clearly visible.

Differential Power Analysis (DPA) collects many traces and applies statistical correlation
to extract key bits even from noisy measurements. It works against implementations that
resist SPA by making individual traces unreadable. Given enough traces, the signal
averages out from the noise.

DPA remains practical against embedded systems, smart cards, and any hardware without
explicit countermeasures. The attack requires physical access to the device or access to
the power supply line.

Tools: ChipWhisperer provides open-source hardware and software for power analysis.

```text
git clone https://github.com/newaetech/chipwhisperer
# hardware: ChipWhisperer-Lite or similar target board
```

## Cache timing attacks

On modern CPUs, memory access time depends on whether data is in cache. An operation that
accesses different memory addresses depending on key bits will take measurably different
time depending on the cache state. Flush+Reload and Prime+Probe are the standard
measurement techniques.

Flush+Reload (Yarom and Falkner, 2014): the attacker shares a memory page with the victim
(common in shared libraries), flushes a cache line, waits for the victim to execute, then
measures the reload time. A fast reload means the victim accessed that cache line; a slow
one means it did not.

This can recover AES keys from OpenSSL and similar implementations through the table
lookups in the AES T-table implementation. The T-table accesses are key-dependent; the
cache timing reveals which table entries were accessed.

Counter: constant-time implementations of AES use hardware AES-NI instructions or
bitsliced software implementations that avoid key-dependent memory accesses. Testing
whether a target uses these is part of implementation review.

## Electromagnetic leakage

EM analysis collects electromagnetic emissions from a device. The attack is similar to
power analysis but does not require electrical contact: a near-field probe positioned near
the chip is sufficient.

EM attacks are practical against devices that are physically accessible but where attaching
to the power line is difficult. IoT sensors, payment terminals, and HSMs inside enclosures
are all candidates.

## Spectre and Meltdown class attacks

Spectre (Kocher et al., 2018) exploits speculative execution in modern CPUs. The CPU
speculatively executes instructions across privilege boundaries, leaves a cache footprint,
and the footprint is measurable even after the speculation is rolled back.

Practical implications for cryptanalysis:

- A process running in a shared cloud environment can potentially read memory belonging
  to another process or to the hypervisor
- JavaScript running in a browser tab can potentially read memory from other tabs or the
  browser process
- Cross-VM attacks in cloud environments are documented and have been demonstrated in
  research environments

The relevance for red team work is in cloud environments where a compromised workload
shares a physical host with a target workload. Spectre variants remain partially
unmitigated; full mitigation requires disabling optimisations that carry significant
performance cost.

## AI-assisted signal extraction

The noise in power and EM traces is the main obstacle to practical attacks. Machine
learning, particularly convolutional neural networks trained on labelled traces, improves
signal extraction significantly on noisy hardware without the statistical volume required
by classical DPA.

Deep learning side-channel analysis (Maghrebi et al., 2016, and subsequent work) trains a
CNN to classify traces directly into key hypotheses. Against targets without hardware
countermeasures, CNN-based attacks require fewer traces than classical DPA and generalise
better across different measurement conditions.

This matters operationally for targets where collecting a large trace set is impractical
due to time constraints or access limitations.

## Remote timing attacks

Timing attacks that work over a network are practical against protocols that leak timing
information in their responses. The classic examples:

Lucky13 (Al Fardan and Paterson, 2013): a timing side-channel in CBC-mode HMAC verification
in TLS allowed remote key recovery with enough queries. Patched in TLS implementations but
illustrates the category.

RSA decryption timing (Brumley and Boneh, 2003): timing differences in modular
exponentiation in OpenSSL allowed RSA private key recovery over a local network. Fixed
with constant-time Montgomery multiplication, but variants appear in new implementations.

Bleichenbacher oracle attacks on RSA PKCS#1 v1.5: a 1998 attack that remained exploitable
in practice through 2018 via ROBOT and related findings because many TLS implementations
still supported the padding scheme. The attack requires many oracle queries but is fully
remote.

For red team engagements, testing for timing oracle vulnerabilities in TLS and custom
crypto implementations is a standard step. Tools: `tlsfuzzer`, `timing-attack` Python
library, manual measurement with `openssl s_time`.
