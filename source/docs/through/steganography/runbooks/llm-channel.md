# Runbook: LLM-based covert channel

Encoding messages in AI-generated text by exploiting the probability distribution over
tokens. The receiver, running the same model with the same key, decodes the bits from the
generated text without any visible sign that a message was transmitted.

## Concept

At each step, a language model assigns probabilities to every possible next token. Standard
sampling chooses the next token according to those probabilities. If both parties share a
secret that deterministically controls which token is chosen, that choice encodes bits.

The receiver runs the same model, observes the tokens in the text, and reverses the
process: given the model's distribution at each step and the shared key, what bits does
each token choice represent?

The resulting text is coherent, contextually appropriate, and statistically
indistinguishable from text produced by normal sampling. There is no modification of an
existing file; the message is in the generation process.

## METEOR

METEOR (Minimum Entropy Trajectory Optimization) is the most cited practical
implementation. It bins the probability distribution into groups and maps message bits to
groups. A token is chosen from the group corresponding to the next bit sequence.

Install:

```text
pip install transformers torch
git clone https://github.com/s-nlp/meteor-steg
cd meteor-steg
pip install -r requirements.txt
```

The repository uses GPT-2 as the default model. Encode a message:

```python
from meteor import encode

model_name = 'gpt2'
shared_key = 'operational_key_2024'
prompt = 'The quarterly report highlights the following key findings:'
message = 'beacon: host1 active, awaiting instruction'

cover_text = encode(
    message=message,
    key=shared_key,
    model=model_name,
    prompt=prompt,
    num_tokens=200
)
print(cover_text)
```

The output is a plausible-sounding business text. Send it as an email body, a document
comment, a social media post, or any text channel the two parties share.

Decode at the receiver:

```python
from meteor import decode

recovered = decode(
    text=cover_text,
    key=shared_key,
    model=model_name,
    prompt=prompt
)
print(recovered)
```

## Bandwidth and limitations

METEOR achieves roughly 1 to 3 bits per token. GPT-2 generates around 50 tokens per
second on a CPU. Practical throughput is around 50 to 150 bits per second, or about 6 to
18 bytes per second.

For the operational use cases where this channel makes sense (transmitting a 32-byte key,
a short command, a hostname and port) the bandwidth is adequate. For anything larger, use
a different channel.

The channel requires:

- The same model weights on both sides. GPT-2 weights are 548MB. Agree on the exact
  checkpoint; different versions of the weights produce different probability distributions
  and decoding will fail.
- The same prompt. The prompt conditions the probability distribution; even a single
  character difference breaks decoding.
- The text must arrive unmodified. Autocorrect, email clients that reflow paragraphs, or
  any system that edits the text will break decoding. Use channels that guarantee byte-exact
  delivery: paste sites, raw email bodies, code comments in a shared repository.

## Larger models

GPT-2 is detectable as GPT-2 by AI content classifiers. Using a larger, less recognisable
model reduces this risk. Any HuggingFace causal language model works with the METEOR
framework:

```python
model_name = 'mistralai/Mistral-7B-v0.1'
# requires GPU for reasonable speed
```

Mistral-7B at 4-bit quantisation runs on a single 6GB GPU. The probability distributions
are different from GPT-2, so the text it generates does not carry the statistical signature
of a GPT-2 output. This matters if the receiver is monitoring for AI-generated text from
specific models.

## Operational use

This channel is suited for:

- Establishing a shared secret for a subsequent higher-bandwidth channel
- Passing a short command or URL when all other channels are monitored
- Initial beaconing from an implant that cannot make outbound network connections but can
  post to a monitored text channel (a ticketing system, a shared document)

The channel is not suited for bulk data transfer, for environments where you cannot install
GPT-2 or similar model weights, or for situations where text is automatically edited or
reformatted.

Agree on the protocol out-of-band: the model name, the prompt format, the shared key, and
the delivery channel. Do not transmit the key through the same channel you are trying to
establish.
