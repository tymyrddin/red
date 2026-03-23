# Runbook: deobfuscation pipeline

A structured approach to recovering readable structure from a binary that has been deliberately
obfuscated. The goal is not to read every instruction but to remove enough noise that the
logic becomes tractable.

## Identify the obfuscation type

The technique informs the tooling. Common forms and their signatures:

Control flow flattening: the disassembly shows a dispatcher loop with a state variable that
routes execution between blocks. There are no natural call chains; almost everything goes through
one central switch or comparison sequence.

Opaque predicates: conditional branches where one path is never taken, but the condition is
constructed to look non-trivial. The branch destinations will be structurally asymmetric in terms
of how much real code they contain.

VM-based obfuscation: a custom bytecode interpreter running inside the binary. Look for a fetch,
decode, dispatch loop operating on a separate stack or register file. `strings` will often
reveal no meaningful output; the real logic lives inside the VM handler table.

Use `rabin2 -I` and `strings` as a first pass. Load into Ghidra or IDA Pro and look at the
function list: a small number of very large functions, or a flat graph with no clear call
hierarchy, are both indicators of flattening.

## Set up angr

angr is a Python binary analysis framework built on the VEX IR. Install it in a virtual
environment:

```text
pip install angr
```

Load the binary:

```python
import angr

proj = angr.Project('./target', auto_load_libs=False)
```

`auto_load_libs=False` avoids loading system libraries, which speeds up analysis considerably
for most targets.

## Resolve opaque predicates with symbolic execution

Symbolic execution explores paths through the binary by treating inputs as symbolic values rather
than concrete ones. An opaque predicate resolves to a constant regardless of input; symbolic
execution will find that one branch is unsatisfiable.

```python
cfg = proj.analyses.CFGFast()

for node in cfg.graph.nodes():
    block = proj.factory.block(node.addr)
    # look for conditional branches with only one reachable successor
```

For a targeted approach, use `angr.SimulationManager` to explore from a specific address and
observe which branches are reachable:

```python
state = proj.factory.blank_state(addr=0x401000)
sm = proj.factory.simulation_manager(state)
sm.explore()

print([hex(s.addr) for s in sm.deadended])
```

Unreachable branches identified this way can be patched to unconditional jumps in the binary,
flattening the dead code.

## Taint tracking

Taint tracking marks attacker-controlled input and follows it through the binary to observe where
it influences execution. This is useful for identifying where decryption keys or config values
are derived.

In angr, use `state.memory` and symbolic variables to mark input bytes as tainted and inspect
which conditions they affect:

```python
tainted = claripy.BVS('input', 8 * length)
state.memory.store(input_addr, tainted)
sm = proj.factory.simulation_manager(state)
sm.explore(find=target_addr)

if sm.found:
    print(sm.found[0].solver.eval(tainted, cast_to=bytes))
```

## IR simplification passes in Ghidra

For control flow flattening, a Ghidra script can identify the dispatcher state variable and
rewrite the graph. The approach:

1. Identify the state variable: the variable written before every dispatch and read at the top
   of the dispatcher block.
2. Propagate constant values backwards from each case block to the preceding assignment.
3. Relink predecessors directly to the appropriate case block, bypassing the dispatcher.

Community scripts for this exist for common protectors (Obfuscator-LLVM, Themida). For custom
obfuscation, write the pass against P-code using Ghidra's Python API:

```python
from ghidra.program.model.pcode import PcodeOp

listing = currentProgram.getListing()
for instr in listing.getInstructions(True):
    pcode_ops = instr.getPcode()
    # inspect CBRANCH ops with constant destinations
```

## Output

The result of a deobfuscation pass is not a clean binary. It is a set of patches and annotations
that make the real logic readable. Document:

- which branches were patched to unconditional
- which blocks are dead code
- what the dispatcher state variable maps to in terms of logical blocks

Apply patches with radare2:

```text
r2 -w target
[0x00401000]> wa jmp 0x401050 @ 0x401020
```

Re-analyse in Ghidra or IDA Pro after patching to get the benefit of the decompiler on the
cleaned graph.
