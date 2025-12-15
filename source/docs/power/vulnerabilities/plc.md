# PLC security testing

![PLCs](/_static/images/ot-plcs.png)

Testing the brains that have no concept of security.

Programmable Logic Controllers are the workhorses of industrial automation. They read sensors, execute logic, control actuators, and do it all in milliseconds, reliably, for decades. They're marvels of engineering designed for harsh environments, real-time performance, and absolute reliability.

They're also, almost universally, completely insecure.

This isn't a criticism of PLC manufacturers. When these devices were designed, security wasn't part of the threat model. PLCs were supposed to be in locked control rooms, on isolated networks, programmed only by trusted engineers with physical access. The assumption was that if you could reach a PLC on the network, you were authorised to be there.

That assumption is now catastrophically wrong, but the PLCs remain. Testing PLC security requires understanding both what's possible and what's safe. Unlike HMI testing where you're working with familiar web technologies, PLC testing involves industrial protocols, real-time constraints, and the very real possibility of causing physical damage if you're not careful.

## Authentication mechanisms (or lack thereof)

Most PLCs have minimal authentication, if any. The security model is "if you can reach me on the network, you can program me".

### PLC authentication models

No authentication at all is common in older PLCs. Siemens S7-300/400, Allen-Bradley PLC-5 and SLC 500, older Modicon PLCs, and many others simply don't ask for credentials. If you can send them the right protocol messages, they'll execute your commands.

Password protection exists in some PLCs but is often weak. The password is typically a short numeric code or simple string. Some PLCs have a single password for all access. Others have separate passwords for reading vs writing, but both are often set to defaults.

Role-based access is found in newer PLCs like Siemens S7-1200/1500, Rockwell ControlLogix v21+, and modern Schneider PLCs. Different users can have different permissions. However, these features are often disabled because they complicate legitimate access.

Physical key switches on many PLCs control whether the PLC accepts program changes. Positions typically include RUN (execute program), STOP (halt execution), and PROGRAM (accept programming). These are physical security controls, not network security controls. If someone has network access, they can often bypass key switch positions through protocol commands.

### Testing authentication

Testing PLC authentication is straightforward but requires appropriate tools and extreme caution. The goal is to determine what authentication exists and whether it can be bypassed, not to actually make unauthorised changes to production systems.

At UU P&L, testing the turbine control PLCs (Siemens S7-315) revealed no authentication whatsoever. Using 
[Snap7](http://snap7.sourceforge.net/), a free open-source library for S7 communication we can do a 
🐙 [status dump](https://github.com/ninabarzh/power-and-light/blob/main/vulns/s7_plc_status_dump.py).

This connected successfully with no authentication required. Further testing revealed the ability to 🐙 [read memory 
areas](https://github.com/ninabarzh/power-and-light/blob/main/vulns/s7_read_memory.py), 
🐙 [download the PLC program](https://github.com/ninabarzh/power-and-light/blob/main/vulns/s7_readonly_block_dump.py), and 
theoretically upload modified programs (not tested on production system).

The reactor control PLCs (also Siemens S7-400) had password protection enabled. However, testing revealed the password 
was a four-digit numeric code. Four digits means 10,000 possible combinations. 
🐙 [Brute forcing is trivial](https://github.com/ninabarzh/power-and-light/blob/main/vulns/plc_password_bruteforce.py). 

This isn't recommended on production systems (it takes time and generates traffic), but in a test environment it 
found the password in under 20 minutes. The password was 1234, which is simultaneously predictable and depressing.

## Project file download attacks

Most PLCs allow downloading their programs for backup, analysis, or modification. If authentication is weak or absent, attackers can download programs containing valuable information.

### What project files contain

The complete control logic showing exactly what the PLC does and how it does it. IP addresses and network configurations for connected devices. Setpoints and operational parameters (temperature limits, pressure thresholds, timing values). Comments and documentation that explain the logic. Sometimes passwords or credentials embedded in the code.

### Downloading PLC programs

The process varies by manufacturer but the concept is consistent. Connect to the PLC using its programming protocol. 
Issue a program download command. Receive the program data. Save it for analysis.

Some PLC platforms (notably legacy Siemens S7‑300/400) permit 
🐙 [program block upload](https://github.com/ninabarzh/power-and-light/blob/main/vulns/s7_readonly_block_dump.py) via 
their native protocol. Others (such as Allen‑Bradley Logix) 
🐙 [expose operational metadata](https://github.com/ninabarzh/power-and-light/blob/main/vulns/ab_logix_tag_inventory.py) 
like tags, but not complete program logic, without proprietary engineering tools.


At UU P&L, downloading the turbine PLC programs revealed detailed control logic including turbine startup sequences, 
overspeed protection algorithms, temperature and vibration monitoring, emergency shutdown conditions, and integration 
points with safety systems.

The programs also contained comments (in German, because Siemens) explaining the logic. One comment translated to 
"TODO: Add proper input validation here - currently assumes sensors always return valid values". This explained why 
sensor failures occasionally caused unexpected PLC behaviour.

## Logic upload and download testing

The inverse of downloading programs is uploading them. If you can upload modified logic to a PLC, you can change 
how it controls physical processes.

### The danger of logic modification

This is where PLC testing becomes genuinely dangerous. Uploading malicious or incorrect logic can cause equipment 
damage, safety incidents, or operational disruption. This type of testing should only be done on test systems, 
simulators, or with extensive safety precautions.

### Testing approach for logic upload

Do not test on production systems unless you have explicit approval, comprehensive understanding of the process, the 
ability to immediately revert changes, and operators standing by to intervene if needed.

The safe approach is to test on a spare PLC in a lab environment, use PLC simulators, or create a test environment 
that mimics production but controls nothing physical.

At UU P&L, testing was done on a spare Siemens S7-315 PLC obtained from the old brewery equipment. This PLC was 
identical to the production turbine PLCs but wasn't connected to anything that could be damaged.

The test demonstrated that uploading modified logic was possible (Illustrative pseudocode demonstrating unauthenticated PLC logic upload):

```
# Conceptual demonstration (pseudocode)

# 1. Read compiled logic block from PLC (read-only)
compiled_block = plc.read_block(block_type="OB", block_number=1)

# 2. Replace block with attacker-controlled logic
# (In practice, this logic was created using Siemens engineering tools)
attacker_block = compiled_block_with_modified_logic

# 3. Write block back to PLC
plc.write_block(attacker_block)

# 4. Restart PLC to execute new logic
plc.restart()
```

The upload succeeded. The PLC executed the modified logic. If this had been a production system controlling a turbine, 
the modified logic would have controlled the turbine.

The demonstration for UU P&L stakeholders used a PLC connected to indicator lights. The original program made the 
lights blink in sequence. The modified program made them blink randomly. Simple, visual, and completely harmless. 
But it demonstrated that an attacker with network access could upload arbitrary logic to PLCs.

## Memory manipulation

PLCs have various memory areas that can be read and written. Directly manipulating memory allows changing values without modifying the program logic.

### PLC memory areas

- Inputs (I) reflect the state of physical input devices. In theory read-only (reflecting real-world state), but some 
PLCs allow forcing input values for testing.
- Outputs (Q) control physical output devices. Writing to outputs causes immediate physical actions.
- Flags (M) are internal memory used by the program for calculations and temporary storage.
- Data blocks (DB) store structured data, configuration parameters, and persistent values.
- Timers (T) and Counters (C) are specialised memory areas for timing and counting operations.

### Reading memory

Reading memory is generally safe when performed sparingly; however, aggressive or high‑frequency polling can impact 
PLC performance. Memory reads allow observation of live process values (sensor readings, actuator states), 
configuration parameters, setpoints, and alarm information. This provides significant insight into system operation 
and enables attack planning, while not directly altering the physical process.

At UU P&L, reading turbine PLC memory revealed current sensor values (temperatures, pressures, speeds), current output 
states (valves open/closed, pumps on/off), setpoints and configuration parameters, and alarm states and counters.

This information alone is valuable for understanding operations and planning attacks, but it doesn't change physical 
state.

### Writing memory

Writing memory directly affects physical processes. This is dangerous and should only be done in controlled conditions.

```
# Conceptual example – DO NOT RUN ON PRODUCTION SYSTEMS

# Write to output memory
plc.write_output(address=0, value=ON)

# Write to configuration data
plc.write_datablock(db=1, offset=0, values=new_parameters)
```

At UU P&L, memory write testing was only demonstrated on the spare PLC. The test showed that writing to output memory 
immediately changed the physical outputs (the indicator lights responded instantly). Writing to data blocks changed 
setpoints and parameters.

On a production system, writing to outputs could open valves, start motors, or change turbine speeds. Writing to 
data blocks could modify temperature limits, pressure setpoints, or timing parameters. All of these could have 
serious operational and safety consequences.

## Coil and register forcing (Modbus)

PLCs that support Modbus TCP have specific functions for forcing coils (discrete outputs) and registers (analog values). These are intended for testing and maintenance but can be exploited.

### Modbus function codes for forcing

- Function code 05 (Write Single Coil) forces an output to ON or OFF.
- Function code 06 (Write Single Register) writes a value to a holding register.
- Function code 15 (Write Multiple Coils) forces multiple outputs simultaneously.
- Function code 16 (Write Multiple Registers) writes multiple register values.

### Read coils and registers

[pyModbus](https://github.com/pymodbus-dev/pymodbus) can be used for 
🐙 [reading coils and registers](https://github.com/ninabarzh/power-and-light/blob/main/vulns/modbus_coil_register_snapshot.py)

### Writing coils and registers

```
Illustrative example (pseudocode – do not run on production systems)

# Force a discrete output (Modbus FC05)
modbus.write_coil(address=0, value=ON)

# Force an analog value (Modbus FC06)
modbus.write_register(address=0, value=new_setpoint)
```

At UU P&L, several PLCs had Modbus gateways for integration with third-party systems. Reading coils and registers 
provided real-time process data. The concerning discovery was that writing was also possible without authentication.

Testing on a non-critical system (the cafeteria refrigeration, which used a small PLC with Modbus) confirmed that 
write commands worked. Writing to `coil 0` turned the refrigeration compressor on or off. Writing to `register 0` 
changed the temperature setpoint.

If the same Modbus gateway existed on turbine systems (it did), and if it allowed writes (it did), then anyone 
with network access could force turbine outputs or change setpoints via simple Modbus commands.

## Program execution flow analysis

Understanding how a PLC program executes helps identify vulnerabilities in the control logic itself, not just in the 
PLC's security mechanisms.

### PLC scan cycle

PLCs execute programs in a continuous cycle:

1. Read inputs from physical sensors
2. Execute program logic
3. Update outputs to physical actuators  
4. Handle communications
5. Repeat

This happens very quickly, typically every 10-50 milliseconds. Understanding this timing is important for timing-based attacks.

### Analysing downloaded programs

Once you've downloaded a PLC program, analysing it to understand the control logic, identify critical functions, find potential vulnerabilities in logic, and locate safety-critical code.

Siemens programs can be analysingd with TIA Portal or STEP 7 (legally licensed). Allen-Bradley programs require RSLogix or Studio 5000. Many programs can also be reverse-engineered from binary format using various tools.

At UU P&L, analysis of turbine PLC programs revealed that overspeed protection relied on a single sensor. If that sensor could be forced to report incorrect values, the PLC would shut down the turbine unnecessarily (denial of service) or fail to shut it down when needed (safety issue).

The startup sequence had specific timing requirements. Steps had to complete within certain windows. If an attacker could introduce delays (by flooding the network, stressing the PLC, or other means), the startup might fail or behave unpredictably.

## Timing attack possibilities

Some PLC operations are timing-sensitive. Disrupting timing can cause failures or bypass safety checks.

### Time-of-check to time-of-use (TOCTOU)

Some PLCs check a condition (is temperature safe?), then perform an action (open valve). If an attacker can change the condition between the check and the action, they can bypass the safety check.

This is difficult to exploit in PLCs because scan cycles are fast, but it's theoretically possible especially with slower PLCs or very carefully timed attacks.

### Scan cycle disruption

If an attacker can make the PLC miss its scan cycle deadline (by flooding it with network traffic, sending malformed packets that take time to process, or exploiting algorithmic complexity in the program), the PLC might enter a fault state or behave unpredictably.

At UU P&L, testing (on the spare PLC) showed that sending a flood of malformed S7comm packets caused the PLC to slow down its scan cycle. At extreme packet rates, the PLC eventually faulted and stopped. This was the same mechanism by which the infamous aggressive nmap scan had crashed a turbine PLC years earlier.

## Firmware extraction

PLC firmware contains the operating system and runtime environment. Extracting and analysing firmware can reveal vulnerabilities in the PLC itself.

### Firmware extraction methods

Download via programming interface if the PLC supports firmware download (some do for backup purposes).

Physical extraction by reading flash memory chips directly (requires physical access and hardware tools).

Intercept firmware updates by capturing update traffic when firmware is being upgraded.

Obtain from vendor websites or support portals where firmware is distributed.

### Firmware analysis

Once extracted, firmware can be analysingd for hardcoded credentials, cryptographic keys, vulnerability in the firmware code itself, and understanding of PLC internal workings.

This level of analysis is beyond typical penetration testing and ventures into vulnerability research. It's mentioned here for completeness but isn't something you'd normally do during an OT security assessment.

At UU P&L, firmware analysis wasn't performed during the assessment. However, the firmware versions were documented and checked against known vulnerabilities. Multiple CVEs existed for those versions, and firmware updates were available but hadn't been applied.

## Physical security considerations

PLC security isn't purely digital. Physical access to PLCs provides additional attack vectors.

### Physical access attacks

Key switch manipulation can change PLC mode from RUN to PROGRAM, allowing programming without network access.

Memory card/SD card access on some PLCs allows copying programs or inserting malicious programs via physical media.

USB ports on newer PLCs can be used for programming, firmware updates, or potentially introducing malware.

Serial ports provide another programming interface, often with even less security than network interfaces.

### Physical security at UU P&L

The turbine hall where PLCs were located had badge access, but the badges were shared among maintenance staff. No logging of who entered when. The PLCs themselves were in unlocked electrical cabinets. Anyone with turbine hall access could physically access PLCs.

The key switches on turbine PLCs were in the RUN position, which prevented local programming. However, the switches were standard DIN rail components that could be removed or defeated with basic tools.

One PLC (reactor control) had a USB port exposed on the front panel. Testing with a USB drive showed the PLC would read files from it. This could potentially be exploited for malware introduction, though crafting such malware would require significant expertise.

The recommendations included locking electrical cabinets containing PLCs, logging badge access to critical areas, considering tamper-evident seals on PLC access panels, and covering or removing unnecessary physical interfaces.

## Testing safely (the most important section)

Everything discussed above is technically possible. Most of it should not be done on production systems.

### Safe testing principles

Test on spare equipment whenever possible. If you have spare PLCs, use them. Set up a test environment that mirrors production but controls nothing physical.

Use simulators when spares aren't available. Most PLC manufacturers provide software simulators. These allow testing protocol interactions without physical PLCs.

Read-only testing on production systems includes querying information, downloading programs for offline analysis, and observing communications. These are generally safe (with appropriate rate limiting) and provide valuable information.

Limit write testing to test environments. Only perform write operations (program uploads, memory writes, output forcing) in controlled test environments where physical consequences are impossible or acceptable.

Get explicit approval for any testing that could affect physical systems. Document exactly what will be tested, when, and what the abort procedures are.

Have rollback procedures ready. Know how to quickly revert any changes. Have backups of original programs. Have operators standing by to take manual control if needed.

### At UU P&L, the testing approach

Production systems: Read-only testing (program downloads, memory reads, protocol analysis). All findings documented without making changes.

Spare PLC: Write testing (program uploads, memory writes, output forcing) demonstrated safely on equipment controlling nothing but indicator lights.

Simulators: Some testing used software PLCs to avoid any risk to production equipment.

Documentation and video: Rather than actually exploiting vulnerabilities on production systems, capabilities were demonstrated on test equipment and documented with screenshots and video. Stakeholders could see what was possible without risking production.

This approach provided comprehensive assessment of vulnerabilities whilst maintaining safety and operational continuity. Not a single production system was disrupted, not a single turbine was affected, and the Archchancellor remained blissfully unaware that PLC security was being tested.

## The uncomfortable truth

PLCs were never designed to be secure. They were designed to be reliable, real-time, and deterministic. Security was someone else's problem, handled by network isolation and physical access controls.

Those controls have failed. PLCs are now on networks that connect to corporate IT, to the internet, to vendor support systems. The assumption that "if you can reach the PLC, you're authorised" is no longer valid.

Yet the PLCs remain, running critical infrastructure, often irreplaceable, and completely insecure by modern standards. At UU P&L, every PLC tested had critical security weaknesses. None could be fixed without replacement, and replacement wasn't an option for equipment that costs hundreds of thousands of euros per unit and would require months of downtime to swap.

The only realistic security measures were compensating controls such as network segmentation to limit who can reach PLCs, network monitoring to detect unauthorised access attempts, application whitelisting on systems that can connect to PLCs, and accepting the residual risk that PLCs themselves cannot be made secure.

This is the reality of OT security. The devices themselves are insecure and will remain so. Security must be built around them, not in them. It's not ideal, it's not what best practices recommend, but it's what's actually achievable with systems that were never designed for security and cannot be made secure without replacement.

The PLCs at UU P&L will continue running, insecure, for years or decades more. The security team's job is to ensure that getting to those PLCs is as difficult as possible, and that if someone does reach them, the intrusion is detected quickly. Perfect security isn't possible. Adequate security through defence in depth is achievable, if imperfect and requiring constant vigilance.
