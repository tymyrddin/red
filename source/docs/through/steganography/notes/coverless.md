# Coverless steganography

Classical steganography modifies a cover file. The modification is the vulnerability: a
detector can compare the stego file against statistical models of unmodified files and flag
anomalies. The modification does not have to be found; it only has to be noticed.

Coverless steganography removes the modification. Instead of modifying an existing image, a
generative system produces a new image that encodes the message by construction. There is
no original to compare against. The stego image is not a modified file; it is a generated
one, and statistically it looks like any other generated image.

## GAN-based coverless: SteganoGAN

SteganoGAN trains a GAN where the generator produces images that encode a given bit sequence,
and a decoder network recovers the bits. The discriminator ensures the images look like
real photographs from the training distribution.

```text
pip install steganogan
```

Encode a message:

```python
from steganogan import SteganoGAN

model = SteganoGAN.load(architecture='dense')
model.encode('cover.png', 'stego.png', 'the payload text or binary string')
```

Decode:

```python
print(model.decode('stego.png'))
```

The `dense` architecture achieves approximately 4.4 bits per pixel on COCO-style images.
The `residual` architecture trades capacity for visual quality. Use the residual variant
for targets that might run image quality metrics; use dense where capacity matters more.

SteganoGAN expects PNG input. For JPEG-heavy delivery channels, save as PNG, encode, and
convert the stego output to high-quality JPEG only after encoding. Do not encode directly
into JPEG-destined images, as JPEG quantisation will corrupt the payload.

## Diffusion-based approaches

Stable Diffusion and similar models generate images from latent noise. The noise vector is
the generative seed; modifying it deterministically encodes information into the output image.
The message is not in the pixels in the classical sense; it is in the generation process.

The Invisible Watermark library provides a practical implementation:

```text
pip install invisible-watermark
```

Embed a 48-bit identifier into a generated image:

```python
from imwatermark import WatermarkEncoder

encoder = WatermarkEncoder()
encoder.set_watermark('bits', [1,0,1,1,0,0,...])  # 48 bits
bgr_img = cv2.imread('generated.png')
bgr_encoded = encoder.encode(bgr_img, 'rivaGan')
cv2.imwrite('stego.png', bgr_encoded)
```

For higher capacity, the research direction is latent diffusion steganography: encoding the
payload into the initial noise tensor before sampling. This requires access to the diffusion
model itself (Stable Diffusion weights run locally), not just the output image. The
advantage is that the encoding is part of the generation process and leaves no detectable
modification artefact in the output.

## Why this matters operationally

The traditional detection workflow is:
1. Obtain the image
2. Compare against statistical models of clean images
3. Flag anomalies

This fails for coverless content because step 3 has no baseline. A generated image with
an embedded payload is statistically identical to a generated image without one. The only
distinguishing feature is knowledge of the encoding scheme, which the detector does not have.

For payload delivery, the practical implication is that per-file detection tools
(stegdetect, zsteg, Aletheia operating on single images) are largely ineffective. Defenders
are pushed toward traffic analysis and behavioural detection rather than file inspection.

The operational constraint is model availability: generating a stego image with a diffusion
model requires either a local GPU or a capable API. For a single delivery, that is manageable.
For a high-volume C2 channel that updates instructions frequently, compute cost becomes
relevant.

## Choosing an approach

For one-time payload delivery where detectability matters more than convenience: diffusion
or SteganoGAN. No modification artefact, no classical steganalysis baseline.

For an ongoing C2 channel where images are generated in bulk: SteganoGAN is faster to run
repeatedly than a full diffusion pipeline.

For environments where neural tools are not available: LSB with encryption still raises the
bar significantly over unencrypted embedding, and is harder to act on even when detected
statistically.
