Trends in steganography
=============================================

Classical methods (LSB substitution, DCT coefficient tweaking) are baseline comparisons
rather than current practice. The field has moved toward neural and generative approaches that
change what detection even means.

- Embedding is now learned, not hand-crafted
- Generation has replaced modification in the most advanced systems
- Steganalysis and embedding are both AI-driven, and locked in an arms race
- Covert channels have expanded beyond images to video, audio, network traffic, and language


.. toctree::
   :maxdepth: 1
   :includehidden:
   :caption: The shift is structural, not incremental:

   neural-embedding.md
   coverless.md
   adversarial-evasion.md
   covert-channels.md