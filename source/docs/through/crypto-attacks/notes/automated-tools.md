# Automated cryptanalysis tools

Symbolic execution, SMT solvers, and formal verification tools have become practical for
attacking cryptographic implementations. Think less "cryptographer with a chalkboard" and
more "CI pipeline that quietly finds your catastrophic mistake at 3am".

## SMT solvers

An SMT (Satisfiability Modulo Theories) solver takes a set of logical constraints and
finds an assignment of variables that satisfies them, or proves none exists. For
cryptanalysis, the constraints describe the relationship between the unknown key, the
known plaintext, and the observed ciphertext. The solver searches for the key.

This works in practice for:

- Weak custom ciphers with short key lengths or insufficient round counts
- Protocols with logical errors that reduce the effective key space
- Finding keys for simple XOR-based encryption or substitution ciphers

Z3 is the most widely used SMT solver:

```python
from z3 import BitVec, BitVecVal, Solver, Extract, sat

# example: crack a 16-bit key from a simple XOR cipher
key = BitVec('key', 16)
plaintext = 0x4865  # known: "He"
ciphertext = 0x5D7A  # observed

s = Solver()
s.add(key ^ BitVecVal(plaintext, 16) == BitVecVal(ciphertext, 16))

if s.check() == sat:
    print(f"Key: {hex(s.model()[key].as_long())}")
```

For more realistic targets, angr (built on Z3) provides symbolic execution of binary code:
the binary is run with symbolic inputs representing the key, and the solver finds an input
that satisfies the output constraint.

```python
import angr, claripy

proj = angr.Project('target_binary', auto_load_libs=False)

key_sym = claripy.BVS('key', 128)  # 128-bit symbolic key
state = proj.factory.blank_state(addr=0x401000)
state.memory.store(KEY_ADDR, key_sym)

sm = proj.factory.simulation_manager(state)
sm.explore(find=SUCCESS_ADDR, avoid=FAIL_ADDR)

if sm.found:
    solution = sm.found[0].solver.eval(key_sym, cast_to=bytes)
    print(f"Key: {solution.hex()}")
```

Symbolic execution of cryptographic code is expensive in time and memory. It is practical
for binaries of reasonable size where the key space is constrained by prior analysis
(reduced-round, short key, known weak implementation).

## Protocol verification tools

Formal verification tools model cryptographic protocols as state machines and check
security properties (authentication, secrecy, forward secrecy) automatically.

ProVerif and Tamarin are the standard tools. They take a formal model of the protocol and
a security property and either prove the property holds or produce an attack trace.

The attack side use: if you have a custom protocol (a proprietary authentication scheme,
a custom TLS-like handshake, an IoT pairing protocol) and can model it in ProVerif syntax,
run the verification and look for attack traces. Protocol designers rarely use these tools;
finding attack traces that were never checked for is a realistic outcome.

```text
# install ProVerif
apt-get install proverif

# model a simple authentication protocol
# see: proverif.inria.fr/manual.pdf for the modelling language
proverif protocol.pv
```

## Automated padding oracle exploitation

padbuster automates CBC padding oracle attacks against web applications. Given a target
URL, an encrypted parameter, and the block size, it systematically decrypts the parameter
byte by byte.

```text
pip install padbuster
padbuster https://target.example.com/action ENCRYPTED_PARAM 8 --encoding 0
```

Each byte requires at most 256 requests; a 16-byte block requires at most 4096 requests.
For parameters with a 128-byte encrypted value, full decryption requires around 32,768
requests. At 100 requests per second this takes under six minutes.

POET and PadBuster variants also support encryption (encrypting arbitrary plaintext using
the oracle) which allows authentication bypass and session forgery.

## Factorisation tools

For RSA attacks, several tools cover the standard attack paths:

RsaCtfTool covers the common CTF and weak-key scenarios: small key, common factor with
another key, low public exponent with small plaintext, Wiener's attack for small private
exponent, and more.

```text
git clone https://github.com/RsaCtfTool/RsaCtfTool
python RsaCtfTool.py --publickey target.pub --decrypt ciphertext.bin
```

For factoring specific large numbers, yafu and msieve implement the General Number Field
Sieve (GNFS), the best known algorithm for factoring large numbers. At 512 bits, GNFS
factoring takes hours to days on modern hardware; at 1024 bits, it requires nation-state
resources or very long time.

## Hash cracking

For hash cracking, hashcat with GPU acceleration is the standard tool. The grounds section
of this site covers the specific hash types encountered in Windows environments (LM, NT,
DCC, DCC2, Cisco type 5).

```text
hashcat -m 1000 -a 0 hashes.txt wordlist.txt          # NT hashes, dictionary
hashcat -m 2100 -a 0 hashes.txt wordlist.txt           # DCC2
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a      # NT, 8-char brute force
```

Rule-based attacks against known password patterns significantly outperform pure brute
force at realistic keyspace sizes. Hashcat's built-in rules (best64.rule, dive.rule) and
custom rules derived from organisation-specific password policies are standard augmentation.
