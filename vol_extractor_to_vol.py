from __future__ import annotations
import struct
import os
import zlib
import json
from typing import NamedTuple, Sequence
from io import BytesIO
from pathlib import Path
import logging
import argparse

VOL_HEADER = b'P\xf0w\xd1\x01\x01\x00\x00'

with open(Path(Path(__file__).parent,'nvft_offsets_ps4.json')) as f:
    NVFT_OFFSETS = json.load(f) 


def decode_num(number: bytes, /) -> int:
    return struct.unpack('<I',number)[0]

def uint32(value: int, /) -> int:
    return value & 0xFFFFFFFF

def some_hash_function(raw_data: bytes, /) -> int:
    """
    thx to https://github.com/algmyr/ alot for helping making this function
    if you can recongise the hash aloghorthim and have a better python implemention let me know!, 
    its likley to be part of jenkins hash functions https://en.wikipedia.org/wiki/Jenkins_hash_function
    """
    byte_length = uint32(len(raw_data))

    golden_ratio1 = uint32(0x9E3779B9)
    uVar4 = uint32(0x9E3779B9)
    uVar6 = uint32(0)
    uVar7 = uint32(byte_length)

    if byte_length >= 12:
        while uVar7 > 11:
            uVar7 -= 12  # 12 byte chunks

            i0 = uint32(struct.unpack("<I", raw_data[:4])[0])
            i1 = uint32(struct.unpack("<I", raw_data[4:8])[0])
            i2 = uint32(struct.unpack("<I", raw_data[8:12])[0])

            raw_data = raw_data[12:]

            uVar6 = uint32(i2 + uVar6)

            uVar4 = uint32(uVar6 >> 13 ^ ((i0 + uVar4) - (i1 + golden_ratio1)) - uVar6)
            golden_ratio1 = uint32(uVar4 << 8 ^ ((i1 + golden_ratio1) - uVar6) - uVar4)
            uVar5 = uint32(golden_ratio1 >> 13 ^ (uVar6 - uVar4) - golden_ratio1)
            uVar4 = uint32(uVar5 >> 12 ^ (uVar4 - golden_ratio1) - uVar5)
            uVar6 = uint32(uVar4 << 16 ^ (golden_ratio1 - uVar5) - uVar4)
            uVar5 = uint32(uVar6 >> 5 ^ (uVar5 - uVar4) - uVar6)
            uVar4 = uint32(uVar5 >> 3 ^ (uVar4 - uVar6) - uVar5)
            golden_ratio1 = uint32(uVar4 << 10 ^ (uVar6 - uVar5) - uVar4)
            uVar6 = uint32(golden_ratio1 >> 15 ^ (uVar5 - uVar4) - golden_ratio1)

        uVar7 = uint32((byte_length - 12) % 12)

    uVar6 = uint32(byte_length + uVar6)

    if uVar7 == 11:
        uVar6 = uint32(raw_data[10] * 0x1000000 + uVar6)
    if uVar7 >= 10:
        uVar6 = uint32(raw_data[9] * 0x10000 + uVar6)
    if uVar7 >= 9:
        uVar6 = uint32(raw_data[8] * 0x100 + uVar6)
    if uVar7 >= 8:
        golden_ratio1 = uint32(golden_ratio1 + raw_data[7] * 0x1000000)
    if uVar7 >= 7:
        golden_ratio1 = uint32(golden_ratio1 + raw_data[6] * 0x10000)
    if uVar7 >= 6:
        golden_ratio1 = uint32(golden_ratio1 + raw_data[5] * 0x100)
    if uVar7 >= 5:
        golden_ratio1 = uint32(golden_ratio1 + raw_data[4])
    if uVar7 >= 4:
        uVar4 = uint32(uVar4 + raw_data[3] * 0x1000000)
    if uVar7 >= 3:
        uVar4 = uint32(uVar4 + raw_data[2] * 0x10000)
    if uVar7 >= 2:
        uVar4 = uint32(uVar4 + raw_data[1] * 0x100)
    if uVar7 >= 1:
        uVar4 = uint32(uVar4 + raw_data[0])

    uVar4 = uint32(uVar6 >> 13 ^ (uVar4 - golden_ratio1) - uVar6)
    golden_ratio1 = uint32(uVar4 << 8 ^ (golden_ratio1 - uVar6) - uVar4)
    uVar6 = uint32((golden_ratio1) >> 13 ^ ((uVar6) - (uVar4)) - (golden_ratio1))
    uVar5 = uint32(uVar6 >> 12 ^ (uVar4 - golden_ratio1) - uVar6)
    golden_ratio1 = uint32(uVar5 << 16 ^ (golden_ratio1 - uVar6) - uVar5)
    uVar4 = uint32(golden_ratio1 >> 5 ^ (uVar6 - uVar5) - golden_ratio1)
    uVar6 = uint32(uVar4 >> 3 ^ (uVar5 - golden_ratio1) - uVar4)
    golden_ratio1 = uint32(uVar6 << 10 ^ (golden_ratio1 - uVar4) - uVar6)

    result = uint32(golden_ratio1 >> 15 ^ (uVar4 - uVar6) - golden_ratio1)
    return result


def decompress_vol(vol_file: bytes) -> bytes:
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


def compress_vol(normal_file: bytes, temp_patch_nvft: str = None) -> bytes:
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


class VolumeFileLink(NamedTuple):
    filename_hash: int
    #unknown_number: int
    file_data_start: int
    #unknown_number2: int
    #unknown_number3: int
    file_data_size: int
    
    def __bytes__(self):
        return struct.pack('<6I',self.filename_hash,0,self.file_data_start,0,0,self.file_data_size)
    
    @classmethod
    def from_bytes(cls, file_link_bytes: int):
        filename_hash,_,file_data_start,_,_,file_data_size = struct.unpack('<6I',file_link_bytes)
        return cls(filename_hash,file_data_start,file_data_size)
    
    def __hash__(self):
        return self.filename_hash
    
    def __eq__(self: 'VolumeFileLink' ,other: VolumeFileLink | int):
        if isinstance(other,int):
            return self.filename_hash == other
        else:
            return tuple(self) == tuple(other)


def build_vol_header(datablocks_offset,decompressed_data_size: int, filenames_hashes: Sequence[int]) -> bytes | int:
    """
    buckets = list(range(0,len(filenames_hashes)+1,5))
    if len(buckets) < 2:
        buckets = [0,len(filenames_hashes)]
    
    
    if len(buckets) > 2 and not len(buckets) % 2:
        buckets.pop(2)
    
    for index,_ in enumerate(buckets):
        if index == 0:
            continue
        buckets[index] -= 1
    
    buckets[-1] = len(filenames_hashes)
    buckets_size = len(buckets).bit_length() - 1
    """
    buckets = [0,len(filenames_hashes)] # lol no hashmap for u
    buckets_size = 0

    logging.debug(str((buckets,buckets_size)))
    
    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        for hashy in filenames_hashes:
            hashy = hashy % (1 << buckets_size)  
            logging.debug(str(buckets[hashy]))
            logging.debug(str(buckets[hashy+1]))
    
    packed_buckets = struct.pack(f'<{len(buckets)}H',*buckets)
    
    if pad_amnt := len(packed_buckets) % 4:
        packed_buckets += b'\x00' * (4 - pad_amnt)
    
    vol_header = bytearray(b'\x00\xC0\xE6\x9E\x00\x00' +
                    struct.pack('B',buckets_size) + 
                    b'\x00\x1C\x00\x00\x00' + 
                    struct.pack("<I", len(filenames_hashes)) + 
                    b'\x00\x00\x00\x00' + 
                    struct.pack("<I", datablocks_offset) + 
                    struct.pack("<I", decompressed_data_size) +
                    packed_buckets
                )
    

    vol_header[16:16+4] = struct.pack('<I',len(vol_header))
    
    logging.debug(str(vol_header.hex(' ')))
    logging.debug(str(len(vol_header)))
    
    
    
    return vol_header, buckets_size

def read_header(vol: BytesIO) -> tuple[int,int,int.int]:
    vol.seek(0xc)
    file_count = decode_num(vol.read(4))
    filelinks_offset = decode_num(vol.read(4)) # offset 0x10
    
    vol.seek(0x14)
    datablocks_offset = decode_num(vol.read(4))    
    
    vol.seek(0x18)
    decompressed_data_size = decode_num(vol.read(4))
    
    vol.seek(filelinks_offset)
    
    return file_count,filelinks_offset,datablocks_offset,decompressed_data_size


def extract_decompressed_vol(vol: BytesIO, output_folder: Path):
    file_count,filelinks_offset,datablocks_offset,decompressed_data_size = read_header(vol)
    
    file_links = [VolumeFileLink.from_bytes(vol.read(0x18)) for _ in range(file_count)]
    filenames = [filename.decode('ascii') for filename in vol.read((datablocks_offset) - vol.tell()).split(b'\x00') if filename]

    for file_link,filename in zip(file_links,filenames):
        assert file_link.filename_hash == some_hash_function(filename.lower().encode('ascii'))
        vol.seek(file_link.file_data_start)
        with open(Path(output_folder, filename),'wb') as f:
            f.write(vol.read(file_link.file_data_size))

def pack_to_decompressed_vol(vol_write_read_plus: BytesIO, output_folder: Path):
    files = [file for file in Path(output_folder).iterdir() if file.is_file()]
    
    header,buckets_size = build_vol_header(0,0,{some_hash_function(filename.name.lower().encode('ascii')) for filename in files})
    files.sort(key = lambda filename: some_hash_function(filename.name.lower().encode('ascii')) % (1 << buckets_size))

    vol_write_read_plus.write(header)

    for file in files:
        vol_write_read_plus.write(bytes(VolumeFileLink(0,0,0)))

    for file in files:
        vol_write_read_plus.write(file.name.encode('ascii') + b'\x00')
    
    datablocks_offset = vol_write_read_plus.tell()
    
    if pad_amnt := vol_write_read_plus.tell() % 32:
        vol_write_read_plus.write(b'\x00' * (32 - pad_amnt))
    
    file_links = []

    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        for index, x in enumerate(files):
            logging.debug(str((x.name, index)))
    
    for index, file in enumerate(files):
        file_data = file.read_bytes()
        file_links.append(VolumeFileLink(some_hash_function(file.name.lower().encode('ascii')),vol_write_read_plus.tell(),len(file_data)))
        vol_write_read_plus.write(file_data)
        
      # if not index == len(files)-1: # for whatever reason, the last file is not padded, yes this makes the entire file not be in a 32 bytes bound, no clue why
      #    if pad_amnt := f.tell() % 32:
      #        f.write(b'\x00' * (32 - pad_amnt))
    decompressed_data_size = vol_write_read_plus.tell()
    
    vol_write_read_plus.seek(len(header))
    for file_link in file_links:
        vol_write_read_plus.write(bytes(file_link))

    vol_write_read_plus.seek(0)
    vol_write_read_plus.write(build_vol_header(datablocks_offset,decompressed_data_size,{some_hash_function(filename.name.lower().encode('ascii')) for filename in files})[0])


def vol2files(input_vol: Path, output_folder: Path):
    with open(input_vol,'rb') as f:
        data = BytesIO(decompress_vol(f.read()))
    
    extract_decompressed_vol(data,output_folder)

def files2vol(input_folder: Path, output_file: Path, nvft_file: Path):
    open(output_file,'w').close()
    with open(output_file,'rb+') as f:
        pack_to_decompressed_vol(f,input_folder)
        f.seek(0)
        data = f.read()
        new_data = compress_vol(data,(Path(output_file).name,nvft_file))
    with open(output_file,'wb') as f:
        f.write(new_data)


def main(args=None):
    parser = argparse.ArgumentParser(description='Simple tool to extract .vol files, and pack files back to .vol (used in Shantae and the Pirate\'s Curse)')
    
    parser.add_argument('input_file',help='Input file to extract from, or folder with files to pack into')
    parser.add_argument('output_file',help='Output location to extract the vol, or output file to pack the files into vol',nargs='?', default=1)

    parser.add_argument('-p', '--pack_to_vol', help='The path to the nvft file, to patch in new offsets and lengths, if packing back into vol', nargs='?', type = str, const=False)

    args = parser.parse_args(args)

    if args.pack_to_vol is False:
        raise ValueError('Please provide a path to the nvft file!')
    
    if args.pack_to_vol:
        if args.output_file == 1:
            args.output_file = Path(os.getcwd(),Path(Path(args.input_file).name).with_suffix('.vol'))
        print(args.output_file)
        files2vol(args.input_file,args.output_file,args.pack_to_vol)
    else:
        if args.output_file == 1:
            args.output_file = os.getcwd()
        new_path = Path(args.output_file,Path(args.input_file).stem)
        new_path.mkdir(exist_ok=True)
        
        vol2files(args.input_file,new_path)


if __name__ == '__main__':
    main()
