# Power, heat, and related inconveniences

*Extracts from the notebooks of Ponder Stibbons, Lecturer in Applied Inconveniences*

Unseen University Power & Light Co. (UU P&L) is Ankh-Morpork’s quietly indispensable utility and loudly inexplicable 
liability. It exists to provide electricity, heat, steam, chilled water, and other strictly necessary phenomena to a 
city that has learned, through experience, that darkness and cold tend to encourage the wrong sort of civic 
participation.

From a distance, UU P&L appears to be a company. Up close, it is more accurately described as an agreement between 
physics, bureaucracy, and several things that ought not to be awake at the same time.

The company operates out of a series of repurposed basements, annexes, and one structure that insists, at length and 
with diagrams, that it was never meant to be a building at all. These spaces were acquired piecemeal over decades, 
usually after someone noticed that something important was already happening there.

![Company in Ankh Morpork](/_static/images/power-light.png)

Power generation began conventionally enough: turbines, boilers, switchgear. Unfortunately, “conventionally” at 
Unseen University merely means “before anyone added cleverness”.

Over time, incremental upgrades were applied:

* control systems installed to improve reliability
* monitoring systems installed to understand why reliability had not improved
* safety systems installed to prevent the monitoring systems from becoming involved

Each layer was added with grant-funded optimism and the budgetary discipline of a wizard who has discovered 
procurement. Nothing was ever removed. Instead, new systems were encouraged to coexist politely with the old ones, 
a policy that has worked surprisingly well provided one does not ask *why*.

UU P&L’s Hex Steam Turbine Control System forms the mechanical heart of the operation. Designed in an era when PLCs 
were expected to outlive their designers, it still governs massive steam turbines through hardwired logic and 
polling loops that have never heard of cybersecurity and are deeply suspicious of it. These systems are stable, 
predictable, and utterly unforgiving of modern assumptions.

Adjacent to this is the Bursar’s Automated Alchemical Reactor Controls, a system that technically counts as 
“process control” if one is generous with definitions. It regulates volatile alchemical reactions that convert 
raw thaumic input into usable energy, provided the Bursar is not having a bad day. Control logic must account 
for both chemical states and metaphysical side effects, which has led to an impressive uptime record and an 
equally impressive incident log.

The Library Environmental Management System is treated with the reverence usually reserved for unexploded ordnance. 
It maintains temperature, humidity, and ambient magical stability within the University Library, where even minor 
fluctuations can destabilise L-space, rearrange shelving across dimensions, or summon things that insist they were 
only browsing. Changes to this system require approvals, rituals, and at least one librarian standing very still.

Finally, the City-Wide Distribution SCADA ties everything together, managing power and heat delivery across 
Ankh-Morpork. It interfaces with substations, pumping stations, and civic infrastructure that predate the concept 
of “the grid” but have been grandfathered into it anyway. The SCADA system is continuously monitored, occasionally 
understood, and absolutely not to be rebooted during business hours.

From a testing perspective, UU P&L represents a perfect storm of legacy technology, operational fragility, 
undocumented behaviour, and city-level consequences. Every probe must be deliberate, every assumption questioned, 
and every “small test” treated as if it might cause a blackout, a flood, or a minor magical anomaly. 
Sometimes all three.

I became involved when the lights in the High Energy Magic Building began flickering in a pattern that, when charted, 
spelled out the word *NO* in High Aetheric. This was initially dismissed as coincidence until the kettle in the 
Senior Common Room began screaming.

![OT Controls](/_static/images/ot-controls.png)

UU P&L technically has a control room. In practice, it has several areas where people stand while staring at numbers 
and making meaningful noises. The main operations console is operated by staff who understand three things extremely well:

1. Which alarms can be ignored
2. Which alarms must never be ignored
3. Which alarms indicate that something has developed opinions

Control engineers visit infrequently but intensely. They arrive with laptops, diagrams, and expressions of restrained 
despair, adjust a few parameters, and leave behind handwritten notes reading “DO NOT TOUCH THIS AGAIN” in at least 
three handwriting styles.

In short, UU P&L keeps Ankh-Morpork running. Most days. 


