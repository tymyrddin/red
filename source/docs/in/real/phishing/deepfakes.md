# Deepfake video

AI-generated video impersonation is distinct from voice cloning in both tooling and use case,
though the two are frequently combined. Voice cloning operates on audio: a convincing phone
call or audio message. Video deepfakes operate on the visual layer as well, and the use cases
reach into contexts where a phone call would not be plausible: a video message from a senior
executive, a live Teams or Zoom call where the target expects to see the person they are
speaking to, or an identity verification step that requires the user to appear on camera.

The technology has matured unevenly. Pre-recorded deepfake video is significantly more capable
than live video substitution. Live deepfakes introduce latency, require continuous processing
power, and produce artefacts under certain lighting and motion conditions that a careful observer
may notice. Pre-recorded material can be refined until it reaches an acceptable quality threshold.

## Pre-recorded video messages

The most operationally reliable application is a short pre-recorded message from an authority
figure: a CEO authorising a transaction, a CFO confirming wire transfer instructions, a director
approving an exception to a standard policy. The target receives the video through a channel
that does not allow them to interrupt or question the sender: a shared link, an attachment, a
message in a platform where the sender appears unavailable for follow-up.

BEC attacks that previously relied on email impersonation increasingly use video as an
additional layer of authority. The logic is that a video message from a recognisable face is
harder to dismiss as a phishing attempt than a text email, even when the underlying social
engineering is identical. The target who would check with IT before actioning an unusual email
instruction is less likely to question a video in which a senior figure personally confirms
the request.

Source material requirements are modest. A few minutes of publicly available video, the kind
available from conference appearances, investor calls, and media interviews, provides enough
for a short message. The generated output is most convincing at under thirty seconds, which
is also the format most consistent with how senior executives actually send informal video
messages.

## Live video calls

Real-time face-swapping tools that run as virtual webcam inputs are available and functional,
though with greater operational constraints. The primary challenge is latency: processing
introduces a delay of several frames that becomes visible during rapid head movement or
expressive speech. Controlled environments help: a target who believes the call quality is
poor is less likely to interpret visual artefacts as a sign that the video has been
manipulated.

Live deepfake impersonation has been used for video-based hiring interviews, internal IT
support calls, and executive communications that were assumed to be too sensitive for email.
In each case the value is the same as any impersonation technique: the target's prior
relationship with the person being impersonated does work that a text-based lure cannot.

## Identity verification bypass

Video-based identity verification, used by banks, carriers, cryptocurrency exchanges, and
onboarding platforms, typically asks the user to display an identity document and perform a
liveness check: turn to the side, blink, hold up a finger. These checks were designed to
defeat static image injection. Most are not designed to detect generated video streams.

Tools that inject pre-generated or real-time synthesised video into a webcam stream can pass
liveness checks that do not involve challenge-response patterns too complex to anticipate.
Where the verification system does implement unpredictable challenges, some pre-generated
video tooling allows rapid composition of short gesture clips that address the challenge in
near real time.

## Operational notes

The tells that experienced observers use to identify deepfakes are mostly motion-dependent:
unnatural blinking rates, lighting that does not track head movement, hair and glasses that
behave inconsistently at the edges. In a low-resolution video call or a compressed shared
video, these artefacts are frequently invisible.

Selecting source material with consistent lighting and a relatively static background reduces
the generation difficulty. Avoiding extended sequences where the subject looks directly into
the camera reduces the risk of eye contact anomalies. Keeping generated video short reduces
the cumulative probability that the target notices something wrong.

## Cross-references

- [Vishing and callback phishing](vishing.md): AI voice cloning for the audio-only variant
- [Building a cover identity](../pretext/personas.md): synthetic identity construction that underpins video impersonation personas
