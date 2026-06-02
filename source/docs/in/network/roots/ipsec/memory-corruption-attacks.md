# Memory corruption attacks

## Attack pattern

Memory corruption attacks against IPsec implementations exploit vulnerabilities in how packets are processed, parsed, and handled within operating system kernels, IKE daemons, and network stacks. These attacks target flaws in buffer management, packet reassembly, and protocol parsing to achieve remote code execution, denial of service, or unauthorised access to sensitive memory contents. Successful exploitation can compromise the entire IPsec infrastructure, bypassing cryptographic protections entirely.

```text
1. Memory corruption attacks [OR]

    1.1 Kernel IPsec stack overflows [OR]

        1.1.1 Stack-based buffer overflows in ESP/AH packet processing [AND]
            1.1.1.1 Exploit oversized payloads in incoming ESP/AH packets
            1.1.1.2 Overwrite local stack variables [AND]
                1.1.1.2.1 Gain control of return addresses
                1.1.1.2.2 Trigger kernel-level code execution

        1.1.2 Heap overflow in SA state allocation and management [AND]
            1.1.2.1 Exploit insufficient bounds checks in SA creation
            1.1.2.2 Overwrite adjacent heap structures [AND]
                1.1.2.2.1 Corrupt session state
                1.1.2.2.2 Redirect execution flow

        1.1.3 Integer overflows in packet size calculations [AND]
            1.1.3.1 Supply crafted packet sizes exceeding limits
            1.1.3.2 Wrap arithmetic to bypass checks [AND]
                1.1.3.2.1 Allocate insufficient buffer
                1.1.3.2.2 Cause memory corruption or kernel crash

        1.1.4 Use-after-free vulnerabilities in SA garbage collection [AND]
            1.1.4.1 Free SA structures prematurely
            1.1.4.2 Trigger access to dangling pointers [AND]
                1.1.4.2.1 Manipulate freed memory contents
                1.1.4.2.2 Escalate privileges or crash stack

    1.2 IKE daemon remote code execution [OR]

        1.2.1 Buffer overflows in IKE message parsing [AND]
            1.2.1.1 Supply malformed IKE_SA_INIT or IKE_AUTH payloads
            1.2.1.2 Overwrite daemon memory regions [AND]
                1.2.1.2.1 Hijack execution flow
                1.2.1.2.2 Execute arbitrary code as daemon user

        1.2.2 Format string vulnerabilities in logging functions [AND]
            1.2.2.1 Inject format specifiers in IKE messages
            1.2.2.2 Exploit improper printf-style handling [AND]
                1.2.2.2.1 Read sensitive memory
                1.2.2.2.2 Redirect control flow

        1.2.3 Memory corruption in certificate parsing and validation [AND]
            1.2.3.1 Supply malformed X.509 certificates
            1.2.3.2 Exploit ASN.1 parsing flaws [AND]
                1.2.3.2.1 Cause heap/stack corruption
                1.2.3.2.2 Bypass validation or execute arbitrary code

        1.2.4 Race conditions in IKE state machine handling [AND]
            1.2.4.1 Trigger concurrent message handling
            1.2.4.2 Exploit non-atomic updates [AND]
                1.2.4.2.1 Corrupt internal state tables
                1.2.4.2.2 Facilitate remote code execution or denial-of-service

    1.3 Packet parsing vulnerabilities [OR]

        1.3.1 Length validation bypass in IPsec header processing [AND]
            1.3.1.1 Craft packets with inconsistent length fields
            1.3.1.2 Circumvent buffer size checks [AND]
                1.3.1.2.1 Overwrite memory regions
                1.3.1.2.2 Trigger daemon or kernel crash

        1.3.2 ASN.1 parsing flaws in X.509 certificate handling [AND]
            1.3.2.1 Supply nested or malformed ASN.1 structures
            1.3.2.2 Exploit decoder logic [AND]
                1.3.2.2.1 Cause heap corruption
                1.3.2.2.2 Enable code execution or certificate bypass

        1.3.3 Integer underflow in ICV (Integrity Check Value) calculation [AND]
            1.3.3.1 Provide crafted packet sizes
            1.3.3.2 Wrap arithmetic to bypass checks [AND]
                1.3.3.2.1 Trigger allocation of undersized buffers
                1.3.3.2.2 Overwrite memory adjacent to buffers

        1.3.4 Crafted transform payload exploitation [AND]
            1.3.4.1 Manipulate cryptographic transform fields
            1.3.4.2 Exploit parser assumptions [AND]
                1.3.4.2.1 Trigger invalid memory access
                1.3.4.2.2 Corrupt SA state or crash process

    1.4 Fragmentation reassembly flaws [OR]

        1.4.1 IP fragmentation overlap attacks (Teardrop variants) [AND]
            1.4.1.1 Supply overlapping fragments
            1.4.1.2 Exploit kernel reassembly logic [AND]
                1.4.1.2.1 Overwrite memory during merge
                1.4.1.2.2 Cause kernel panic or denial-of-service

        1.4.2 Fragment reassembly buffer exhaustion [AND]
            1.4.2.1 Flood victim with many fragments
            1.4.2.2 Exhaust memory allocated for reassembly [AND]
                1.4.2.2.1 Prevent legitimate packet processing
                1.4.2.2.2 Induce denial-of-service

        1.4.3 Length validation bypass through fragmentation [AND]
            1.4.3.1 Craft fragments with inconsistent total length
            1.4.3.2 Bypass bounds checks [AND]
                1.4.3.2.1 Cause memory overwrite
                1.4.3.2.2 Trigger kernel or daemon crash

        1.4.4 Off-by-one errors in reassembly state tracking [AND]
            1.4.4.1 Supply fragments that trigger edge-case buffer indexing
            1.4.4.2 Exploit index miscalculations [AND]
                1.4.4.2.1 Overwrite adjacent memory
                1.4.4.2.2 Cause denial-of-service or code execution
```

## Why it works

-   Protocol complexity: IPsec's complex packet structures and multiple header layers create numerous parsing edge cases.
-   Performance pressures: Optimised packet processing often sacrifices security checks for speed.
-   Legacy code bases: Many IPsec implementations contain decades-old code with known vulnerability patterns.
-   State management complexity: SA state tracking and packet reassembly involve complex memory management.
-   Kernel integration: Kernel-resident IPsec stacks operate with high privileges, amplifying impact.
-   Fragmentation handling: IP fragmentation reassembly is notoriously difficult to implement securely.

## Counter moves

Memory corruption attacks is the case here. Strong IKE configuration and pruning weak proposals are the fix. Defenders' notes on this are under [traffic patterns as evidence](https://blue.tymyrddin.dev/docs/counter/network/).
