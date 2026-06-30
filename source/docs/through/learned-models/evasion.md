# Evasion

Evasion is an attack at inference time. The model is already trained, already deployed, already scoring live inputs. An
attacker does not touch the weights or the training set. They craft an input that the model gets wrong, and they craft
it on purpose, knowing how the model tends to decide.

What makes evasion specific to a learned model is the gap between what the model measures and what
a human would. A written rule fails in ways a person can read off the rule. A classifier fails along
a decision boundary that nobody drew by hand and nobody can fully see. The attacker who finds a
point just on the wrong side of that boundary has an input that is malicious in effect and benign in
score, and the two facts can sit together without contradiction.

## Deployed classifiers

- Malware and file classifiers that score an upload before it reaches a sandbox.
- Moderation and abuse models that pass or hold user content.
- Fraud scoring that clears or flags a transaction.
- Login risk engines weighing device and behavioural features.
- Spam and phishing filters reading message text and headers.

In each case the model produces a label and a confidence, and something downstream acts on that
label without re-deriving it. The evasive input is built for exactly that handover.

## Working the boundary

*Perturbing a malicious file until the classifier clears it*: A model that scores executables on
extracted features can be probed feature by feature. An attacker appends benign-looking sections,
pads with strings the model associates with clean files, or reorders content, changing the score
without changing what the file does when run. The sample is genuinely the same malware; the model's
view of it has moved across the boundary.

*Black-box probing of an abuse classifier*: An attacker with no access to the weights still has the
output. By submitting many variants and watching which are held and which pass, they map the local
shape of the decision boundary and then phrase the violating content to sit just inside the
permitted region. No gradient is needed, only patience and a query budget.

*Feature-space evasion of a fraud model*: Fraud scoring leans on a handful of behavioural features:
velocity, amount, device age, time of day. An attacker who understands which features carry weight
can shape a transaction to read as low-risk, spreading activity across the dimensions the model
watches so that no single feature crosses a threshold while the whole still completes the fraud.

*Transferable examples crafted against a surrogate*: An attacker who cannot query the target
heavily trains a stand-in model on similar data, crafts evasive inputs against the stand-in, and
finds that many of them carry over. Adversarial inputs frequently transfer between models that
learned the same task, so the boundary of a private model can be approximated without ever touching
it directly.

*Semantic evasion the pipeline lens cannot see*: Input sanitisation checks that an input is
well-formed, in range, free of injection. An evasive input passes all of that, because it is a real,
valid input. The image is a real image. The transaction is a real transaction. The misclassification
is in the statistics, not in the format, so the layer that guards the format waves it through.

*Confidence shaping to dodge a review threshold*: Some pipelines send only low-confidence cases to a
human. An attacker who can nudge an input toward high confidence on the wrong label avoids review
entirely. The model is sure, the queue stays short, and the case that most needed eyes is the one
least likely to get them.

## Military and geopolitical applications

Nation-states and military organisations have encountered evasion in several operational domains, where the gap between
what a classifier sees and what a human sees has become a tactical variable.

### Adversarial patterns on reconnaissance imagery

[Research into full-coverage adversarial textures](https://www.preprints.org/manuscript/202603.2394) has demonstrated
that adversarial tarps and painted surface patterns on military hardware can cause satellite image classifiers to
register an armoured convoy as agricultural infrastructure or featureless terrain. The pattern looks unusual to a human observer,
but to the classifier it injects features associated with a benign class. An armoured division moving under such cover
may never register as a military threat in an automated scan.

### Decoy systems and adversarial patches

[Research into AI-based military target detection](https://www.researchgate.net/publication/406953991_AI-based_military_target_detection_under_camouflage_conditions_implications_for_capability_sustainment_and_defence_procurement)
demonstrates that a lightweight decoy fitted with a heat source can be given a surface patch that causes an enemy
classifier to assign it the signature of a high-value missile system. Resources are directed toward neutralising the decoy while the real
system, lacking the patch, registers as low-priority. The adversarial patch does nothing for a human observer; it works
only on the model being targeted.

### Infrared evasion against autonomous drone targeting

[Research into multispectral evasion attacks](https://arxiv.org/abs/2604.06865) has demonstrated that portable
infrared emitters projecting adversarial patterns can cause drone targeting systems to misclassify terrain or divert
munitions from intended targets. In some configurations the attack may cause a system to
re-classify its own infrastructure as a hostile target. No access to the drone’s network is required and no trace of
intrusion remains.

### Surface modification and treaty verification

Surface textures applied to missile silo lids can shift the features an image classifier extracts, causing it to
register the site as featureless terrain. Treaty-monitoring systems that rely on automated counting of silo signatures
may then undercount. The modification is deniable as routine maintenance.

### Adversarial camouflage in the Russia-Ukraine conflict

Russian armoured vehicles in the Russia-Ukraine conflict have appeared with large geometric patterns in orange and
black, a design with little obvious human-eye camouflage value. Some analysts have suggested these are consistent
with adversarial patch logic, targeting automated classification systems rather than the eyes of opposing troops,
though the specific systems and mechanisms remain contested. Whether or not that accounts for the observed geometry, the conflict has
made evasion a live operational concern rather than a laboratory scenario.

The dynamic is self-reinforcing. A classifier trained to identify tanks gets updated when it encounters a new pattern;
new patterns appear; retraining begins again. The loop has no stable end state.

### AI-generated phishing and malware evasion

Evasion is not only a physical or image-domain problem.
The [GREYVIBE group](https://healsecurity.com/greyvibe-hackers-leverage-chatgpt-and-google-gemini-to-fuel-cyberattacks/),
linked to Russian state interests, uses commercial language models including ChatGPT and Google Gemini to generate
phishing lures and malware components specifically designed to evade AI-powered email filters and content moderation
systems. The approach inverts the usual attacker posture: rather than probing the target classifier directly, the
attacker outsources the evasion work to a generative model, which produces novel phrasing and code structures that the
target classifier has not seen during training. Each generated variant is cheap; the classifier's coverage is
necessarily bounded.

### Autonomous malware navigating device UI

[PROMPTSPY](https://thenextweb.com/news/when-malware-learns-to-think), an Android backdoor, uses
the Gemini API to navigate victim devices autonomously. The model interprets the device's UI in real time and generates
swipes, taps, and navigation commands to accomplish attacker objectives, including resisting uninstallation by steering
around the interface elements that would remove it. The evasion here is behavioural: the malware's actions resemble user
interaction rather than automated execution, making heuristic detection harder. The classifier watching for suspicious
process behaviour sees what looks like a user operating the device.

## Hardening against boundary probing

Adversarial testing against the deployed model, not only accuracy against a clean validation set. A
model can score well on held-out data and still have a boundary that bends under deliberate pressure;
the two properties are measured differently and one does not imply the other.

Treating confidence as a feature an attacker can target, rather than a measure of safety. A score
near the threshold and a score far from it both warrant attention when the input arrived from an
untrusted source.

Keeping a human in the path for high-consequence decisions, with the model's output framed as one
input rather than the verdict. The point of evasion is to make the automated step the only step;
keeping a second step removes that leverage.

Monitoring for clustered near-boundary inputs from a single source, which can indicate probing in
progress rather than a run of genuinely ambiguous cases.

## Counter moves

The defender's view of AI placed inside security operations, and where evasion bites, is in the
purple notes on [inputs to the model](https://purple.tymyrddin.dev/docs/ai-security/input/).

## Related

* [Inputs to the model](https://purple.tymyrddin.dev/docs/ai-security/input/)
* [Attack path mapping](https://purple.tymyrddin.dev/docs/threat-modelling/attack-path-mapping/)
* [The calibration view: what is and is not worth fearing](https://purple.tymyrddin.dev/docs/adversarial-ai/)
