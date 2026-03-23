# Adversarial evasion of steganalysis

Modern steganalysis uses machine learning classifiers trained on known steganographic
algorithms. Given a large set of clean images and stego images produced by a known tool
(steghide, F5, JSteg), a classifier learns to distinguish them with high accuracy. SRNet
and EfficientNet-based detectors trained this way achieve over 90% accuracy against the
tools they were trained on.

The weakness is the phrase "the tools they were trained on". A detector trained on
steghide detects steghide. It does not reliably detect a novel embedding algorithm, and
it does not detect embedding that was explicitly optimised to fool it.

## Training against detectors

The principle is straightforward: if the detector is differentiable (or can be approximated
as such), the encoder can be trained to minimise the detector's confidence score alongside
the other objectives (imperceptibility, payload recovery).

The standard approach in research (Volkhonskiy et al., Tang et al., Shi et al.) is to add
the detector as an adversary during encoder training:

```text
loss = payload_recovery_loss + lambda1 * perceptual_loss + lambda2 * detector_loss
```

where `detector_loss` is the cross-entropy of the detector's prediction on the encoder
output. Minimising it pushes the encoder to produce stego images the detector classifies
as clean.

After training, the encoder produces images that fool that specific detector. The catch
is that a different detector trained on the resulting images will eventually catch them.
The defence has to retrain; the attack has to retrain. This is the arms race.

## Practical approach: target the deployed detector

Most organisations do not run cutting-edge research classifiers. They run commodity tools:
stegdetect, Aletheia with default models, or commercial products based on SRM features.

The practical evasion approach is:

1. Identify which tool or class of tool the target environment is likely to run.
2. Obtain or replicate it.
3. Test your chosen embedding method against it.
4. If the tool flags the output, adjust the embedding parameters or switch to a method
   the tool was not trained on.

Most classical tools fail against neural embedding by default, because their training data
did not include neural stego images. Running your payload through HiDDeN or SteganoGAN and
then testing with stegdetect will usually show clean results, not because you broke the
detector, but because it was never trained for that type of embedding.

## Defeating SRM-based detectors

Spatial Rich Model (SRM) features are the basis for most classical learned steganalysis.
They measure high-order statistics of prediction residuals. The key insight for evasion is
that SRM features are computed in the spatial domain using fixed filter kernels. Embedding
that distributes changes into the DCT frequency domain (as in JPEG steganography) partially
evades SRM-based detectors trained on spatial LSB changes.

For JPEG-based delivery:

```text
f5 -e payload.txt -p password cover.jpg stego.jpg
```

F5 uses matrix encoding to reduce the number of DCT coefficient changes per bit embedded,
minimising the statistical footprint. Against a spatial SRM classifier, F5-embedded images
score lower suspicion than LSB-modified images at equivalent payload capacity.

## Testing your output

Before using any embedding method operationally, test it against the most capable freely
available detector:

```text
pip install aletheia
aletheia auto-test --image stego.png
```

Aletheia's `auto-test` command runs the image against multiple trained models and reports
detection probability for each. An image flagged by none of the default models is not
provably undetectable; it means the embedding does not match any training distribution
the tool knows about. That is still operationally useful.

For a more targeted test, run against the specific algorithm you are trying to evade:

```text
aletheia srnet-predict --image stego.png --model srnet-model-alaska2.pkl
```

If the score is above 0.5 (indicating stego content), change the embedding parameters
(lower the payload density, change the cover image, or switch to a different tool) and
test again.

## Cover image selection

Detectors are less effective on high-activity image regions (textured areas, foliage,
fabric) than on smooth regions (sky, skin, flat backgrounds). Embedding into high-activity
covers at low payload density is harder to detect than embedding into smooth covers at
high density.

For operational use, select cover images with high spatial frequency content. Avoid
synthetic images with large uniform regions. Natural photographs of outdoor scenes,
crowds, or textured objects are better covers than product shots or illustrations.
