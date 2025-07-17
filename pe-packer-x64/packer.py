import argparse
import lief

def pad_data(data, al) -> bytearray:
    data_bytearray = bytearray()

    def align(x, al):
        if x % al == 0:
            return x
        else:
            return x - (x % al) + al

    new_data = data + ([0] * (align(len(data), al) - len(data)))

    for d in new_data:
        if isinstance(d, str):
            data_bytearray.extend(d.encode())
        else:
            data_bytearray.append(d)

    return data_bytearray


parser = argparse.ArgumentParser(description='Pack PE binary')
parser.add_argument('input', metavar="FILE", help='input file')
parser.add_argument('-o', metavar="FILE", help='output', default="packed.exe")

args = parser.parse_args()

pe = lief.PE.parse("unpacker.exe")
file_alignment = pe.optional_header.file_alignment
section_data_padded = pad_data(list(open(args.input, "rb").read()), file_alignment)

section = lief.PE.Section(".rsrc")
section.content = memoryview(section_data_padded)
section.size = len(section_data_padded)
section.characteristics = 0x40000040 # \\ IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA \\

pe.add_section(section)
pe.optional_header.sizeof_image = 0

builder = lief.PE.Builder(pe)
builder.build()
builder.write("out.exe")
