# AI-assisted cryptanalysis

Machine learning is being applied to cryptanalysis in several areas. The results are
genuinely useful in some domains and significantly overhyped in others. The useful framing
is that AI is a power tool that accelerates certain attacks on weak targets, not a skeleton
key that breaks strong ones.

## Where it actually helps

Side-channel signal extraction is the most productive application. Power and EM traces are
noisy; classical DPA requires many traces to extract a statistically significant signal.
CNNs trained on labelled trace sets (traces paired with known key hypotheses) learn to
extract key-dependent features directly, reducing the required trace count significantly.

Deep learning side-channel analysis (Maghrebi et al., 2016) demonstrated CNN-based attacks
that outperform classical DPA on masked implementations where standard correlation fails.
The practical advantage is fewer measurements required, which matters when physical access
to a device is limited in time.

Distinguishing weak random number generators from truly random output is a second area.
Classical statistical tests (NIST SP 800-22) have fixed sensitivity; a trained classifier
can detect weaker biases that the fixed tests miss. This is useful for evaluating embedded
device RNGs and identifying targets whose key material may be weaker than it appears.

Differential and Linear Cryptanalysis assistance: neural networks have been trained to
approximate the differential distribution tables of reduced-round ciphers, allowing
faster search for the best differential characteristics. This does not break full AES
but accelerates analysis of reduced-round variants and custom lightweight ciphers.

## Gohr's work on Speck

The most cited example of neural-assisted cryptanalysis is Aron Gohr's 2019 paper on the
Speck cipher. A neural distinguisher trained on Speck-32/64 achieved accuracy comparable
to the best known differential distinguisher, and was used as a component in a key
recovery attack on 11-round Speck-32/64 that outperformed the best known previous result.

Gohr's neural distinguisher is a practical example of AI improving on hand-crafted
cryptanalysis in a specific, constrained setting. The key qualification is that Speck-32
is a reduced-key, reduced-round cipher used in constrained environments; the result does
not generalise to full AES or ChaCha20.

```text
git clone https://github.com/agohr/deep_speck
pip install numpy tensorflow
python speck_gohr.py  # train the distinguisher
```

## Automated vulnerability discovery in implementations

Large language models and code analysis tools are increasingly effective at finding
cryptographic misuse in source code. Not cryptanalysis of the algorithm, but identification
of implementation mistakes: hardcoded keys, insecure modes, missing MAC, reused IVs,
weak randomness sources.

Tools integrating LLM-based analysis:

```text
# semgrep rules for cryptographic misuse
pip install semgrep
semgrep --config=p/cryptography target_codebase/

# CodeQL crypto queries
codeql database create codebase-db --language=python --source-root=target_codebase/
codeql query run crypto-misuse.ql --database=codebase-db
```

These tools find things like `AES.new(key, AES.MODE_ECB)`, `random.random()` used to
generate keys, or `hashlib.md5()` for password storage. The findings are not algorithmic
breaks; they are implementation errors that make the crypto ineffective.

## Where it does not help

Breaking full AES, ChaCha20, or properly implemented elliptic curve cryptography. No
neural network or ML model is going to find the AES key from ciphertext. The algorithms
are designed to resist exactly this kind of statistical analysis; their security margins
are sufficient even against model-assisted search.

Breaking RSA given properly sized keys and proper randomness. The RSA problem reduces to
integer factorisation; ML does not improve on the best classical factorisation algorithms
at current key sizes.

Replacing expertise. The useful applications above all require someone who understands
the attack they are accelerating. A CNN that helps extract a key from power traces still
requires someone who understands power analysis enough to set up the measurement, label
the training data, and interpret the results. ML lowers the bar for known attacks; it
does not replace understanding.

## Practical application in engagements

During target assessment, run automated code analysis (semgrep, CodeQL crypto rules) on
any source code accessible. Flag hardcoded keys, ECB mode, MD5 for secrets, and weak
RNG usage. These are common findings in custom-built applications.

For targets running custom or lightweight ciphers (embedded firmware, IoT devices with
custom encryption protocols), apply neural distinguisher techniques if time allows. The
bar is lower than for standard algorithms and AI-assisted attacks may find weaknesses
faster than classical differential analysis.

For side-channel work against hardware targets, use the ChipWhisperer ecosystem and apply
deep learning trace analysis to reduce measurement requirements.
