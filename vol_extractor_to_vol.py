import zlib
import struct
import argparse

VOL_HEADER = b'P\xf0w\xd1\x01\x01\x00\x00'

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


def to_vol(normal_file: bytes) -> bytes:
    compressed_data = zlib.compress(normal_file,wbits=-15)
    return VOL_HEADER + struct.pack('<2I',len(compressed_data),len(normal_file)) + compressed_data

def main(args=None):
    parser = argparse.ArgumentParser(description='Simple tool to extract .vol files, and pack files back to .vol (used in Shantae and the Pirate\'s Curse)')
    
    parser.add_argument('input_file',help='Input file to ethier extract or pack')
    parser.add_argument('output_file',help='Output file of new .vol file or file from .vol')
    
    parser.add_argument('-p', '--pack_to_vol', help='Do you want to pack to a .vol file',action='store_true')
    
    args = parser.parse_args()
    
    with open(args.input_file,'rb') as f:
        data = f.read()
    
    if args.pack_to_vol:
        new_data = to_vol(data)
    else:
        new_data = extract_vol(data)
    
    with open(args.output_file,'wb') as f:
        f.write(new_data)


if __name__ == '__main__':
    main()
