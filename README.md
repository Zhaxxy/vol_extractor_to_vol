# vol_extractor_to_vol
Simple tool to extract .vol files, and pack files back to .vol (used in Shantae and the Pirate's Curse)

# usage
```
usage: vol.py [-h] [-p [PACK_TO_VOL]] input_file output_file

Simple tool to extract .vol files, and pack files back to .vol (used in Shantae and the Pirate's Curse)

positional arguments:
  input_file            Input file to ethier extract or pack
  output_file           Output file of new .vol file or file from .vol

options:
  -h, --help            show this help message and exit
  -p [PACK_TO_VOL], --pack_to_vol [PACK_TO_VOL]
                        The path to the nvft file, to patch in new offsets
```
