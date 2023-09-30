# vol_extractor_to_vol
Simple tool to extract .vol files, and pack files back to .vol (used in Shantae and the Pirate's Curse)

# usage
```
usage: vol_extractor_to_vol.py [-h] [-p [PACK_TO_VOL]] input_file [output_file]

Simple tool to extract .vol files, and pack files back to .vol (used in Shantae and the Pirate's Curse)

positional arguments:
  input_file            Input file to extract from, or folder with files to pack into
  output_file           Output location to extract the vol, or output file to pack the files into vol

options:
  -h, --help            show this help message and exit
  -p [PACK_TO_VOL], --pack_to_vol [PACK_TO_VOL]
                        The path to the nvft file, to patch in new offsets and lengths, if packing back into vol
```
## example extracting .vol
```
python vol_extractor_to_vol.py app\Resource\SCENE_INTRO_BOSS.vol stuff
```

## example packing back to .vol
```
python vol_extractor_to_vol.py stuff\SCENE_INTRO_BOSS app\Resource\SCENE_INTRO_BOSS.vol -p app\nvft
```
