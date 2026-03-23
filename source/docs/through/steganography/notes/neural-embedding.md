# Neural embedding

Classical steganography embeds data by applying hand-crafted rules to a carrier: flip the
least significant bit, adjust a DCT coefficient, modify a palette entry. The rules are fixed
and known; a detector that knows the rules can often find the embedded data statistically,
even without the key.

Neural steganography replaces the hand-crafted rules with learned ones. An encoder network
takes a cover image and a payload, and produces a stego image. A decoder network takes the
stego image and recovers the payload. Both are trained jointly to minimise three things at
once: the perceptual difference between cover and stego, the payload recovery error, and
(in adversarial variants) the probability of detection.

## HiDDeN

HiDDeN (Hiding Data with Deep Networks, Zhu et al., 2018) is the architecture most
subsequent work builds on. The encoder is a convolutional network that distributes payload
bits across the spatial frequency content of the image. The decoder is a second convolutional
network that inverts this. A discriminator network provides a detection signal during
training, pushing the encoder to produce images that are statistically indistinguishable
from unmodified images.

The practical result: at equivalent payload capacity, HiDDeN-trained embeddings are harder
to detect with classical steganalysis tools (SRM, maxSRM) than LSB or F5, because the
embedding is not constrained to any single statistical domain.

Clone and install:

```text
git clone https://github.com/jyp/HiDDeN
cd HiDDeN
pip install -r requirements.txt
```

Encode a payload into a cover image:

```python
import torch
from model.hidden import Hidden

model = Hidden(data_depth=1, hidden_size=32, image_channels=3)
model.load_state_dict(torch.load('pretrained.pth'))

cover = load_image('cover.png')          # (1, 3, H, W) tensor, normalised
payload = torch.randint(0, 2, (1, 1, H, W)).float()

with torch.no_grad():
    stego, _ = model.encoder_decoder.encoder(cover, payload)

save_image(stego, 'stego.png')
```

Decode:

```python
with torch.no_grad():
    decoded = model.encoder_decoder.decoder(stego)
    bits = (decoded > 0).float()
```

## StegaStamp

StegaStamp (Tancik et al., 2020) is a neural steganography system designed for physical
robustness: the embedded data survives printing, photographing, and scanning. The architecture
uses a residual encoder with spatial transformer networks to distribute the payload in a way
that is robust to geometric and photometric distortions.

```text
git clone https://github.com/tancik/StegaStamp
cd StegaStamp
pip install -r requirements.txt
```

Embed a 100-bit message:

```text
python encode_image.py \
  --image cover.png \
  --secret "0110100101010101..." \
  --output stego.png
```

Decode:

```text
python decode_image.py --image stego.png
```

StegaStamp works on JPEG as well as PNG, which matters for payload delivery over channels
that apply compression (social media platforms, email attachments).

## Payload preparation

Neural embedding works on bit sequences. Prepare the payload before embedding:

Encrypt first, then embed. The decoder recovers bits, not meaning; an unencrypted payload
is still readable if the embedding is discovered.

```text
openssl enc -aes-256-cbc -pbkdf2 -in payload.bin -out payload.enc -k passphrase
python encode_image.py --image cover.png --secret $(xxd -b payload.enc | ...) --output stego.png
```

For small payloads (keys, commands, URLs), encode directly as a bit string. For larger
payloads, consider a two-stage approach: embed a URL or decryption key in the image, and
serve the main payload separately.

## Capacity and trade-offs

Neural embedding does not remove the fundamental capacity/imperceptibility trade-off; it
shifts the Pareto frontier. A HiDDeN model trained for high capacity produces more
detectable images than one trained for imperceptibility. The practical ceiling for
undetectable embedding in a 512x512 image using current neural methods is roughly 1000 to
3000 bits depending on image content and detection tolerance.

For a 256-bit AES key plus a 256-bit HMAC, that fits comfortably. For a 100KB shellcode
blob, it does not; use a multi-image scheme or a URL-based two-stage delivery instead.
