import struct
import os
import zlib
import json
from typing import NamedTuple, Sequence, Protocol, ClassVar
from io import BytesIO
from pathlib import Path
import logging
import argparse

VOL_HEADER = b'P\xf0w\xd1\x01\x01\x00\x00'

with open(Path(__file__).parent / 'nvft_offsets_ps4.json') as f:
    NVFT_OFFSETS = json.load(f) 


def _decode_num(number: bytes, /) -> int:
    return struct.unpack('<I',number)[0]


class FilePath(Protocol):
    def read_bytes(self) -> bytes:
        ...
    
    @property
    def name(self) -> str:
        ...

class FileInMemory(NamedTuple):
    name: str
    bytes: bytes

    def read_bytes(self) -> bytes:
        return self.bytes

def scurse_hash(raw_data: bytes, /) -> int:
    """
    thx to https://github.com/algmyr/ alot for helping making this function
    if you can recongise the hash aloghorthim and have a better python implemention let me know!, 
    its likley to be part of jenkins hash functions https://en.wikipedia.org/wiki/Jenkins_hash_function
    """
    byte_length = (len(raw_data)) & 0xFFFFFFFF

    golden_ratio1 = (0x9E3779B9) & 0xFFFFFFFF
    uVar4 = (0x9E3779B9) & 0xFFFFFFFF
    uVar6 = (0) & 0xFFFFFFFF
    uVar7 = (byte_length) & 0xFFFFFFFF

    if byte_length >= 12:
        while uVar7 > 11:
            uVar7 -= 12  # 12 byte chunks

            i0 = (struct.unpack("<I", raw_data[:4])[0]) & 0xFFFFFFFF
            i1 = (struct.unpack("<I", raw_data[4:8])[0]) & 0xFFFFFFFF
            i2 = (struct.unpack("<I", raw_data[8:12])[0]) & 0xFFFFFFFF

            raw_data = raw_data[12:]

            uVar6 = (i2 + uVar6) & 0xFFFFFFFF

            uVar4 = (uVar6 >> 13 ^ ((i0 + uVar4) - (i1 + golden_ratio1)) - uVar6) & 0xFFFFFFFF
            golden_ratio1 = (uVar4 << 8 ^ ((i1 + golden_ratio1) - uVar6) - uVar4) & 0xFFFFFFFF
            uVar5 = (golden_ratio1 >> 13 ^ (uVar6 - uVar4) - golden_ratio1) & 0xFFFFFFFF
            uVar4 = (uVar5 >> 12 ^ (uVar4 - golden_ratio1) - uVar5) & 0xFFFFFFFF
            uVar6 = (uVar4 << 16 ^ (golden_ratio1 - uVar5) - uVar4) & 0xFFFFFFFF
            uVar5 = (uVar6 >> 5 ^ (uVar5 - uVar4) - uVar6) & 0xFFFFFFFF
            uVar4 = (uVar5 >> 3 ^ (uVar4 - uVar6) - uVar5) & 0xFFFFFFFF
            golden_ratio1 = (uVar4 << 10 ^ (uVar6 - uVar5) - uVar4) & 0xFFFFFFFF
            uVar6 = (golden_ratio1 >> 15 ^ (uVar5 - uVar4) - golden_ratio1) & 0xFFFFFFFF

        uVar7 = ((byte_length - 12) % 12) & 0xFFFFFFFF

    uVar6 = (byte_length + uVar6) & 0xFFFFFFFF

    if uVar7 == 11:
        uVar6 = (raw_data[10] * 0x1000000 + uVar6) & 0xFFFFFFFF
    if uVar7 >= 10:
        uVar6 = (raw_data[9] * 0x10000 + uVar6) & 0xFFFFFFFF
    if uVar7 >= 9:
        uVar6 = (raw_data[8] * 0x100 + uVar6) & 0xFFFFFFFF
    if uVar7 >= 8:
        golden_ratio1 = (golden_ratio1 + raw_data[7] * 0x1000000) & 0xFFFFFFFF
    if uVar7 >= 7:
        golden_ratio1 = (golden_ratio1 + raw_data[6] * 0x10000) & 0xFFFFFFFF
    if uVar7 >= 6:
        golden_ratio1 = (golden_ratio1 + raw_data[5] * 0x100) & 0xFFFFFFFF
    if uVar7 >= 5:
        golden_ratio1 = (golden_ratio1 + raw_data[4]) & 0xFFFFFFFF
    if uVar7 >= 4:
        uVar4 = (uVar4 + raw_data[3] * 0x1000000) & 0xFFFFFFFF
    if uVar7 >= 3:
        uVar4 = (uVar4 + raw_data[2] * 0x10000) & 0xFFFFFFFF
    if uVar7 >= 2:
        uVar4 = (uVar4 + raw_data[1] * 0x100) & 0xFFFFFFFF
    if uVar7 >= 1:
        uVar4 = (uVar4 + raw_data[0]) & 0xFFFFFFFF

    uVar4 = (uVar6 >> 13 ^ (uVar4 - golden_ratio1) - uVar6) & 0xFFFFFFFF
    golden_ratio1 = (uVar4 << 8 ^ (golden_ratio1 - uVar6) - uVar4) & 0xFFFFFFFF
    uVar6 = ((golden_ratio1) >> 13 ^ ((uVar6) - (uVar4)) - (golden_ratio1)) & 0xFFFFFFFF
    uVar5 = (uVar6 >> 12 ^ (uVar4 - golden_ratio1) - uVar6) & 0xFFFFFFFF
    golden_ratio1 = (uVar5 << 16 ^ (golden_ratio1 - uVar6) - uVar5) & 0xFFFFFFFF
    uVar4 = (golden_ratio1 >> 5 ^ (uVar6 - uVar5) - golden_ratio1) & 0xFFFFFFFF
    uVar6 = (uVar4 >> 3 ^ (uVar5 - golden_ratio1) - uVar4) & 0xFFFFFFFF
    golden_ratio1 = (uVar6 << 10 ^ (golden_ratio1 - uVar4) - uVar6) & 0xFFFFFFFF

    return (golden_ratio1 >> 15 ^ (uVar4 - uVar6) - golden_ratio1) & 0xFFFFFFFF


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


def compress_vol(normal_file: bytes, temp_patch_nvft: tuple[str,Path] = None) -> bytes:
    # For whatever reason, i need to set this to best compression, otherwise
    # SCENE_LAB_IF_19.vol fucks something up and it cant read the ANIM_SaveMan.vol,
    # very strange (yes the bytes are differnt to the og SCENE_LAB_IF_19.vol even with
    # Z_BEST_COMPRESSION but it fixes it)
    compressed_data = zlib.compress(normal_file,wbits=-15,level=zlib.Z_BEST_COMPRESSION)
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
    """
    a file link or entry in the vol file, it is 0x18 bytes long and contains a hash of the filename, the absoulte offset of the file data in the volume and the file data size
    """
    filename_hash: int
    #unknown_number: int
    file_data_start: int
    #unknown_number2: int
    #unknown_number3: int
    file_data_size: int

    def __bytes__(self):
        return struct.pack('<6I',self.filename_hash,0,self.file_data_start,0,0,self.file_data_size)
    
    @classmethod
    def from_bytes(cls, file_link_0x18_bytes: bytes, /):
        filename_hash,_,file_data_start,_,_,file_data_size = struct.unpack('<6I',file_link_0x18_bytes)
        return cls(filename_hash,file_data_start,file_data_size)
    
    @classmethod
    @property
    def LENGTH(_) -> int:
        return 0x18

    # def __hash__(self):
    #     return self.filename_hash
    
    # def __eq__(self: 'VolumeFileLink' ,other: VolumeFileLink | int) -> bool:
    #     if isinstance(other,int):
    #         return self.filename_hash == other
    #     else:
    #         return tuple(self) == tuple(other)


def _build_vol_header(datablocks_offset: int,decompressed_data_size: int, filenames_hashes: Sequence[int]) -> bytes | int:
    """
    build the header and buckets for the volume, the second return value is the buckets_size, which is used to calculuate the hash jump
    """
    # buckets = list(range(0,len(filenames_hashes)+1,5))
    # if len(buckets) < 2:
        # buckets = [0,len(filenames_hashes)]
    
    
    # if len(buckets) > 2 and not len(buckets) % 2:
        # buckets.pop(2)
    
    # for index,_ in enumerate(buckets):
        # if index == 0:
            # continue
        # buckets[index] -= 1
    
    # buckets[-1] = len(filenames_hashes)
    # buckets_size = len(buckets).bit_length() - 1

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
    
    vol_header = (b'\x00\xC0\xE6\x9E\x00\x00' +
                    struct.pack('B',buckets_size) + 
                    b'\x00\x1C\x00\x00\x00' + 
                    struct.pack("<I", len(filenames_hashes)) + 
                    struct.pack('<I', (6 + 1 + 5 + 4 + 4 + 4 + 4) + len(packed_buckets)) + 
                    struct.pack("<I", datablocks_offset) + 
                    struct.pack("<I", decompressed_data_size) +
                    packed_buckets
                )
    

    # vol_header[16:16+4] = struct.pack('<I',len(vol_header))
    
    logging.debug(str(vol_header.hex(' ')))
    logging.debug(str(len(vol_header)))
    
    
    
    return vol_header, buckets_size

def _read_header(vol: BytesIO) -> tuple[int,int,int,int]:
    """
    reads out the required information about the header and seeks the vol to the start of the file links
    """
    vol.seek(0xc)
    file_count = _decode_num(vol.read(4))
    filelinks_offset = _decode_num(vol.read(4)) # offset 0x10
    
    vol.seek(0x14)
    datablocks_offset = _decode_num(vol.read(4))    
    
    vol.seek(0x18)
    decompressed_data_size = _decode_num(vol.read(4))
    
    vol.seek(0)
    
    return file_count,filelinks_offset,datablocks_offset,decompressed_data_size

def extract_file_vol_decompressed(decompressed_vol: BytesIO, file_link: VolumeFileLink, filename: str) -> bytes:
    if file_link.filename_hash != scurse_hash(filename.casefold().encode('ascii')):
        raise ValueError('filename does not match the filename hash wrong filelink?')
    decompressed_vol.seek(file_link.file_data_start)
    return decompressed_vol.read(file_link.file_data_size)


def get_file_links(decompressed_vol: BytesIO) -> dict[str,VolumeFileLink]:
    """
    ...
    """
    file_count,filelinks_offset,datablocks_offset,_ = _read_header(decompressed_vol)
    decompressed_vol.seek(filelinks_offset)
    
    filelinks = [VolumeFileLink.from_bytes(decompressed_vol.read(VolumeFileLink.LENGTH)) for _ in range(file_count)]
    filenames = [filename.decode('ascii') for filename in decompressed_vol.read((datablocks_offset) - decompressed_vol.tell()).split(b'\x00') if filename]
    
    result = dict(zip(filenames, filelinks,strict=True))
    
    for filename,filelink in result.items():
        if filelink.filename_hash != scurse_hash(filename.casefold().encode('ascii')):
            raise ValueError(f'{filename = } does not match hash of {filelink = } bad vol?')
    
    # decompressed_vol.seek(0)
    return result


def extract_decompressed_vol(decompressed_vol: BytesIO, output_folder: Path):
    for filename,file_link in get_file_links(decompressed_vol).items():
        file = extract_file_vol_decompressed(decompressed_vol,file_link,filename)
        Path(output_folder, filename).write_bytes(file)

def pack_to_decompressed_vol(vol_write_read_plus_output: BytesIO, files: list[FilePath]):
    """
    Pack files into a decompressed vol file, being vol_write_read_plus_output

    :param BytesIO vol_write_read_plus_output: An empty BytesIO object with read and write mode, this is where we will store the output decompressed vol
    :param list[File] files: A list of Files, which must have a name propety which returns a string and a read_bytes method which returns bytes, so a pathlib.Path object will work, this will get packed into the vol 
    """
    # files = [file for file in Path(input_folder).iterdir() if file.is_file()]
    
    header,buckets_size = _build_vol_header(0,0,{scurse_hash(filename.name.casefold().encode('ascii')) for filename in files})
    # files.sort(key = lambda file: scurse_hash(file.name.casefold().encode('ascii')) % (1 << buckets_size))
    files.sort(key = lambda file: scurse_hash(file.name.casefold().encode('ascii')))
    
    vol_write_read_plus_output.write(header)

    # for file in files:
    #    vol_write_read_plus_output.write(bytes(VolumeFileLink(0,0,0)))
    vol_write_read_plus_output.write(b'\x00' * (VolumeFileLink.LENGTH * len(files)))

    for file in files:
        vol_write_read_plus_output.write(file.name.encode('ascii') + b'\x00')
    
    datablocks_offset = vol_write_read_plus_output.tell()
    
    if pad_amnt := vol_write_read_plus_output.tell() % 32:
        vol_write_read_plus_output.write(b'\x00' * (32 - pad_amnt))
    
    file_links = []

    if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
        for index, x in enumerate(files):
            logging.debug(str((x.name, index)))
    
    for index, file in enumerate(files):
        file_data = file.read_bytes()
        file_links.append(VolumeFileLink(scurse_hash(file.name.casefold().encode('ascii')),vol_write_read_plus_output.tell(),len(file_data)))
        vol_write_read_plus_output.write(file_data)
        
        if not index == len(files)-1 or len(files) == 1:
            if pad_amnt := vol_write_read_plus_output.tell() % 32:
                vol_write_read_plus_output.write(b'\x00' * (32 - pad_amnt))

    decompressed_data_size = vol_write_read_plus_output.tell()
    
    vol_write_read_plus_output.seek(len(header))
    for file_link in file_links:
        vol_write_read_plus_output.write(bytes(file_link))

    vol_write_read_plus_output.seek(0)
    vol_write_read_plus_output.write(_build_vol_header(datablocks_offset,decompressed_data_size,{scurse_hash(filename.name.casefold().encode('ascii')) for filename in files})[0])


def vol2files(input_vol: Path, output_folder: Path):
    r"""
    Extract a .vol file into files to ther output_folder
    
    :param Path input_vol: The path to the input vol file, eg Path('app\Resource\SCENE_INTRO_BOSS.vol')
    :param Path output_folder: The path where to extract the files to, eg Path('stuff\SCENE_INTRO_BOSS')
    """
    with open(input_vol,'rb') as f:
        data = BytesIO(decompress_vol(f.read()))
    
    extract_decompressed_vol(data,output_folder)

def files2vol(input_folder: Path, output_file: Path, nvft_file: Path):
    r"""
    Pack loose files back into a .vol file, alongise patching the nvft file with the new decompressed size and compressed size
    
    :param Path input_vol: The path to the input folder with loose files, eg Path('stuff\SCENE_INTRO_BOSS.vol')
    :param Path output_folder: The path to the output .vol file, eg Path('app\Resource\SCENE_INTRO_BOSS.vol')
    :param Path nvft_file: The path to the nvft file, which needs to be patched for this to work, eg Path('app\nvft')
    """
    open(output_file,'w').close()
    with open(output_file,'rb+') as f:
        pack_to_decompressed_vol(f,[file for file in Path(input_folder).iterdir() if file.is_file()])
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
        files2vol(args.input_file,args.output_file,args.pack_to_vol)
    else:
        if args.output_file == 1:
            args.output_file = os.getcwd()
        new_path = Path(args.output_file,Path(args.input_file).stem)
        new_path.mkdir(exist_ok=True)
        
        vol2files(args.input_file,new_path)


if __name__ == '__main__':
    main()
