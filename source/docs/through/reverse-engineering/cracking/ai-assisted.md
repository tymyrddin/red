# AI-assisted reversing

Language model integrations for Ghidra and IDA Pro are useful for speeding up the repetitive
parts of binary analysis. They are not a substitute for reading the disassembly.

## What works

Renaming: feeding a decompiled function to a model and asking for meaningful names for variables
and parameters is faster than doing it manually, and the results are often good enough for
routine library functions and boilerplate code.

Summarising: a one-paragraph summary of what a function does helps when triaging a large binary
with many functions. You can prioritise which ones to look at more carefully without stepping
through all of them.

Pattern recognition: models trained on code can recognise common cryptographic primitives,
sorting algorithms, and hash functions from the decompiled output. This is useful when
compiler optimisation has made the structure non-obvious.

## What does not work

They do not handle novel or heavily obfuscated code reliably. A model that has seen thousands
of examples of standard AES implementations will produce confident but wrong output when it
encounters a custom block cipher or a VM-obfuscated handler. The output looks plausible, which
makes it more dangerous than obvious failure.

They have no access to runtime state. A model reasoning about a decompiled function does not
know what values the registers or memory held when that function was called. Static
decompilation loses that context, and the model cannot recover it.

They hallucinate. Function names, API purposes, and behavioural summaries can be fabricated.
Verify anything the model asserts against the actual disassembly before relying on it.

## Tools

Ghidra: the Gepetto plugin and several community scripts pass decompiled C to an OpenAI-compatible
API and return annotations. `GhidrAI` provides a panel for querying functions directly from the
Ghidra UI.

IDA Pro: the Hex-Rays AI assistant (commercial) integrates with the decompiler. Third-party
plugins such as `gpt4ida` provide similar functionality against the OpenAI API.

Binary Ninja: the Sidekick plugin offers model-assisted analysis with a focus on understanding
function purpose and data structures.

## Workflow

ONLY use AI as a first pass on functions you have not yet looked at. Accept the renames and summary
as hypotheses, not conclusions. When you step through the function or run it under a debugger,
confirm or correct the model's interpretation. Update names accordingly.

The value is in triaging. On a 200-function binary, spending 30 seconds on model-assisted naming
for each function and then focusing manual effort on the 10 that look interesting is faster than
manually naming all 200.

Do not use model output as evidence in a report. Verify every claim against the binary.
