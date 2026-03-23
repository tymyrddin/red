# Intermediate representations and analysis pipelines

Working directly at the assembly level does not scale. Intermediate representations (IR) provide
a normalised, architecture-independent view of a binary that is amenable to scripted analysis.

## Why IR

Assembly is architecture-specific. An analysis pass written for x86 needs to be rewritten for
ARM, MIPS, and every other target. IR lifts assembly into a uniform representation where the
same pass works across architectures.

IR also exposes semantics that are implicit in assembly. Flags, implicit operands, and
instruction side effects are made explicit. This makes certain analyses, particularly data
flow and taint tracking, substantially easier to implement correctly.

## P-code in Ghidra

Ghidra lifts all supported architectures to P-code, a register transfer language with a small
set of operations. Every instruction in the disassembly has a corresponding P-code
representation accessible through the API.

To inspect P-code for a function in the Ghidra Script Manager:

```python
from ghidra.program.model.pcode import PcodeOp

func = getFunctionContaining(currentAddress)
listing = currentProgram.getListing()

for instr in listing.getInstructions(func.getBody(), True):
    for op in instr.getPcode():
        print(op.getMnemonic(), [str(op.getInput(i)) for i in range(op.getNumInputs())])
```

P-code operation types relevant for analysis:

`CALL` and `CALLIND`: direct and indirect function calls. Enumerating these builds a call graph.
`LOAD` and `STORE`: memory reads and writes. Following these identifies what data a function
accesses and produces.
`CBRANCH`: conditional branches. The condition operand is a Varnode; resolving it to a constant
identifies an opaque predicate.
`MULTIEQUAL`: a phi node, indicating a value that depends on which predecessor block was taken.
Present in the high-level IR (HPIL) that feeds the decompiler.

## Microcode in IDA Pro

IDA's microcode is the IR underlying the Hex-Rays decompiler. It is available through the
microcode API from IDA 7.1 onwards. Microcode is represented at multiple maturity levels
from raw (close to assembly) to final (close to the decompiler output).

Access microcode for a function:

```python
import ida_hexrays
import ida_gdl

func = ida_gdl.get_func(here())
mba = ida_hexrays.gen_microcode(
    func,
    None,
    None,
    ida_hexrays.DECOMP_NO_WAIT,
    ida_hexrays.MMAT_GLBOPT2  # after global optimisation
)

for i in range(mba.qty):
    blk = mba.get_mblock(i)
    insn = blk.head
    while insn:
        print(insn.dstr())
        insn = insn.next
```

Microcode is more detailed than P-code but also more coupled to the x86 analysis model. It is
most useful for writing IDA-specific analysis passes where you want to benefit from Hex-Rays'
existing optimisation and type propagation.

## Writing analysis passes

A useful pattern for both tools: write a pass that traverses the IR and emits a structured
report rather than attempting to modify the binary or the analysis in place.

Example Ghidra pass: enumerate all indirect calls in a binary and record the address, the
calling function, and the Varnode representing the call target.

```python
from ghidra.program.model.pcode import PcodeOp

results = []
fm = currentProgram.getFunctionManager()

for func in fm.getFunctions(True):
    for op in func.getPcodeOps():
        if op.getOpcode() == PcodeOp.CALLIND:
            target = op.getInput(0)
            results.append({
                'addr': hex(op.getSeqnum().getTarget().getOffset()),
                'func': func.getName(),
                'target_varnode': str(target)
            })

for r in results:
    print(r)
```

Indirect calls with non-constant targets are candidates for further analysis: they may
indicate function pointer dispatch, virtual calls, or obfuscated control flow.

## Normalising across architectures

When analysing samples across multiple architectures (x86, ARM, MIPS, a RISC-V embedded
target), writing passes against P-code or a shared IR layer means the same code runs against
all of them. The architecture-specific lifting is handled by the framework.

This is particularly relevant for firmware analysis, where binaries for different embedded
targets may implement similar functionality and a cross-architecture pattern search against
the IR is more practical than maintaining separate architecture-specific scripts.
