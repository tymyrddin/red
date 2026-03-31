# Squirrel exfil and exit

Most exfiltration goes undetected not because monitoring is absent but because the monitoring is watching for 
something that no longer matches how data actually moves. Detection rules built around USB transfers and large 
archive creation miss the slow, low-volume channels, the legitimate cloud services used as staging, the file formats 
nobody thought to flag. [The gap between the detection model and the actual technique is the attack surface](../out/exfiltration/index.rst).

This workshop runs participants through that gap from both sides.

## The workshop

The morning session examines the assumptions embedded in detection: what the controls are configured to watch for, 
what counts as an anomaly, and what passes through without registering. The aim is not to catalogue techniques but to 
develop a clear sense of where the model diverges from how data actually moves.

The midday session moves into the lab. Participants simulate exfiltration in an isolated environment, moving small sample files through channels the monitoring is not built to see. Which traces appear, which do not, and why: this is what the exercise is designed to surface.

The afternoon session works backward from the exercise. Teams map the paths explored, identify where the monitoring had no view, and consider what would need to change in the detection model for the gap to close. That map is concrete enough to bring back to a real environment and use.

The workshop runs for a full day. A local lab environment is provided; no cloud access required.

