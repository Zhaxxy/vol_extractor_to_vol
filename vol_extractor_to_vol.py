import zlib
import struct
import argparse
import json
from pathlib import Path

VOL_HEADER = b'P\xf0w\xd1\x01\x01\x00\x00'

with open(Path(Path(__file__).parent,'nvft_offsets_ps4.json')) as f:
    NVFT_OFFSETS = json.load(f)

def extract_vol(vol_file: bytes) -> bytes:
    if not vol_file.startswith(VOL_HEADER):
        raise ValueError('Invalid .vol file')

    compressed_data_size, decompressed_data_size = struct.unpack('<2I',vol_file[8: 8 + 8])
    compressed_data = vol_file[0x10:]
    
    if len(compressed_data) != compressed_data_size:
        raise ValueError('Invalid compressed data size')
    
    decompressed_data = zlib.decompress(compressed_data,wbits=-15)
    
    if len(decompressed_data) != decompressed_data_size:
        raise ValueError('Invalid decompressed data size')
    
    return decompressed_data


def to_vol(normal_file: bytes, temp_patch_nvft: str = None) -> bytes:
    compressed_data = zlib.compress(normal_file,wbits=-15)
    if temp_patch_nvft:
        compressed_size_offset, decompressed_size_offfset = NVFT_OFFSETS[Path(temp_patch_nvft[0]).name]
        
        with open(temp_patch_nvft[1],'rb+') as f:
            f.seek(compressed_size_offset)
            f.write(struct.pack('<I',len(compressed_data)))
            f.seek(0)
            f.seek(decompressed_size_offfset)
            f.write(struct.pack('<I',len(normal_file)))
    
    return VOL_HEADER + struct.pack('<2I',len(compressed_data),len(normal_file)) + compressed_data

def main(args=None):
    parser = argparse.ArgumentParser(description='Simple tool to extract .vol files, and pack files back to .vol (used in Shantae and the Pirate\'s Curse)')
    
    parser.add_argument('input_file',help='Input file to ethier extract or pack')
    parser.add_argument('output_file',help='Output file of new .vol file or file from .vol')
    
    parser.add_argument('-p', '--pack_to_vol', help='The path to the nvft file, to patch in new offsets, if packing back into vol', nargs='?', type = str, const=False)
    
    args = parser.parse_args()

    if args.pack_to_vol is False:
        raise ValueError('Please provide a path to the nvft file!')
    
    with open(args.input_file,'rb') as f:
        data = f.read()
    
    if args.pack_to_vol:
        new_data = to_vol(data,(Path(args.output_file).name,args.pack_to_vol))
    else:
        new_data = extract_vol(data)
    
    with open(args.output_file,'wb') as f:
        f.write(new_data)


if __name__ == '__main__':
    main()
