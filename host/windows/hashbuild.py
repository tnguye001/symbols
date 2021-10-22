# Copyright (c) 2013 Andrew White <awhite.au@gmail.com>

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#


#   Hashbuild
#   Create hashes from PE files by implementing a custom PE loader
#   and normalising parts that change on a page basis


import sys
import struct
import hashlib
import itertools
import os
import os.path

# taken from: https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header

IMAGE_SECTION_HEADER = {
    "TYPE_NO_PAD": 0x00000008,
    "CNT_CODE": 0x00000020,
    "CNT_INITIALIZED_DATA": 0x00000040,
    "CNT_UNINITIALIZED_DATA": 0x00000080,
    "GPREL": 0x00008000,
    "MEM_DISCARDABLE": 0x02000000,
    "MEM_NOT_PAGED": 0x08000000,
    "MEM_SHARED": 0x10000000,
    "MEM_EXECUTE": 0x20000000,
    "MEM_READ": 0x40000000,
    "MEM_WRITE": 0x80000000,
}

# --------------
# Abstract Class
# --------------
class Disk(object):
    """Disk driver for reading the contents of the disk"""

    def __init__(self, disk):
        self.disk = disk

    def read(self):
        """Read all executable files on the disk"""
        pass

    def find(self):
        """Find all PE files on disk"""
        pass


# ----------------------
# Module Implementations
# ----------------------
class Filesystem(Disk):
    """Read files from a mounted disk image"""

    def __init__(self, disk):
        super(Filesystem, self).__init__(disk)

    def read(self, path):
        """Read all PE files on disk"""
        f = open(path, "rb")
        data = f.read()
        f.close()
        return data

    def find(self):
        """Find all PE files on disk"""
        extensions = [".dll", ".exe", ".drv", ".cpl", ".ocx", ".mui"]
        for path, dirs, files in os.walk(self.disk):
            for filename in files:
                name = filename.lower()
                if name[-4:] in extensions:
                    yield filename, os.path.join(path, filename)


# ----------
# Main Logic
# ----------
class HashBuild:
    "Build a hash for each PE file on the disk"

    def __init__(self, args):
        if len(args) != 3:
            print("Usage - hashtest.py <mounted disk> <output file>")
            quit()
        diskfile = args[1]
        hashfile = args[2]
        count = 0

        # build a list of files to read
        files = {}
        count = 0
        disk = Filesystem(diskfile)
        for name, path in disk.find():
            if not (name in files):
                files[name] = []
            files[name].append(path)
            count += 1

        # sort files (based on filename, not path)
        names = list()
        names += files.keys()
        names.sort()

        # output summary
        print("Found {0} files to hash".format(len(names)))

        try:
            filehandle = open(hashfile, "w")
        except Exception as e:
            print("Couldn't open output file: " + hashfile)
            exit(-1)

        # parse PEs and build hashes
        for name in names:
            paths = files[name]
            output = []
            for path in paths:
                physical = disk.read(path)
                data = self.process(physical, path, name)
                if len(data) == 0:
                    # error
                    continue
                hashes, zeroes, virtual, perms = data
                # generate output for file
                output.append(self.output(hashes, zeroes, perms, path, name))

            if len(output) > 1:
                # join into single list of unique hashes
                output = self.filter(output)
            elif len(output) > 0:
                output = output[0]
            else:
                # no output
                continue
            # output hashes for file
            filehandle.write("".join(output))

        filehandle.close()

    def process(self, physical, path, name):
        """Process the PE file and return the hash output"""
        # determine the information required for building the virtual layout
        data = self.parse(physical)
        if not (data):
            if physical != None and len(physical) > 0:
                print("Error - ", path + " " + name)
            else:
                print("Error - ", path + name, " - 0 length")
            return []
        sections, relocs, iat, header_size, aslr_alternation = data
        # build the virtual layout
        virtual, perms = self.expand(physical, sections, header_size)

        other_alterations = []
        for section in sections:
            if section[4] == 3:
                other_alterations.append((section[1],section[0]))

        other_alterations.append(aslr_alternation)
        # determine which values need to be zeroed
        alterations = self.parse_alterations(virtual, relocs, iat, other_alterations)
        # apply the normalisation and split into pages
        pages, zeroes = self.zero(virtual, alterations)
        # hash
        hashes = self.hash(pages)
        return hashes, zeroes, virtual, perms

    def parse(self, physical):
        """Retrieve all necessary details from the PE to allow expansion"""
        data = self.parse_header(physical)
        if data == None:
            # error
            return None
        if len(data) != 5:
            return None
        dir_addr, section_addr, num_sections, header_size, aslr_alternation = data
        relocs, iat = self.parse_directories(physical, dir_addr)
        sections = self.parse_sections(physical, section_addr, num_sections)
        return sections, relocs, iat, header_size, aslr_alternation


    def parse_header(self, physical):
        """Parse the header and return required values"""
        # _IMAGE_DOS_HEADER
        if not (physical):
            return None
        encoding = 'utf-8'
        if physical[0:2].decode(encoding) != "MZ":
            print("Error, invalid dos header")
            return None
        e_lfanew = self.unpack(physical, 0x3C, 4)
        # _IMAGE_NT_HEADERS
        if e_lfanew == 0 or e_lfanew > len(physical):
            print("MSDOS file")
            return None
        if physical[e_lfanew:e_lfanew + 0x2].decode(encoding) != "PE":
            if physical[e_lfanew:e_lfanew + 0x2].decode(encoding) == "NE":
                print("NE file")
                return None
            else:
                print("Error, invalid nt header")
                return None
        nt_header = physical[e_lfanew:e_lfanew + 0xf8]
        PE_magic = self.unpack(nt_header, 0x18, 2)
        if PE_magic == 0x10b:  #PE 32-bit
            # _IMAGE_FILE_HEADER
            file_header = nt_header[0x4:0x18]
            num_sections = self.unpack(file_header, 0x2, 2)
            optional_header_size = self.unpack(file_header, 0x10, 2)
            # _IMAGE_OPTIONAL_HEADER
            header_size = self.unpack(nt_header, 0x18 + 0x3C, 4)  #SizeOfHeaders in Optional Header

            aslr_alternation = (e_lfanew + 0x18 + 28, 4)

            # return location of directories
            directories = e_lfanew + 0x78
            sections = e_lfanew + 0x18 + optional_header_size
            return directories, sections, num_sections, header_size, aslr_alternation

        elif PE_magic == 0x20b:  #PE 64-bit
            # _IMAGE_FILE_HEADER
            file_header = nt_header[0x4:0x18]
            num_sections = self.unpack(file_header, 0x2, 2)
            optional_header_size = self.unpack(file_header, 0x10, 2)
            # _IMAGE_OPTIONAL_HEADER
            header_size = self.unpack(nt_header, 0x18 + 0x3C, 4)
            aslr_alternation = (e_lfanew + 0x18 + 24, 8)
            # return location of directories
            directories = e_lfanew + 0x88
            sections = e_lfanew + 0x18 + optional_header_size
            return directories, sections, num_sections, header_size, aslr_alternation

        else:
            print("Not a 32-bit/64-bit PE - {0:x}".format(self.unpack(nt_header, 0x18, 4)))
            return None

    def parse_directories(self, physical, directories):
        """Parse the directories (_IMAGE_DATA_DIRECTORY) of interest
           (import / basereloc / IAT) for required information"""
        relocs = self.parse_directory(physical, directories + 0x28)
        iat = self.parse_directory(physical, directories + 0x60)
        return relocs, iat

    def parse_directory(self, data, offset):
        """Convert a single directory entry into a pair of rva / size values"""
        vaddr = self.unpack(data, offset + 0x0, 4)
        size = self.unpack(data, offset + 0x4, 4)
        return vaddr, size

    # parse the sections and add the suitable persimissions to sections information
    def parse_sections(self, physical, sections_addr, num_sections):
        """Parse the details of each section - IMAGE_SECTION_HEADER"""
        sections = []
        for i in range(num_sections):
            addr = sections_addr + i * 0x28
            name = physical[addr:addr+ 8].decode('utf8', errors='ignore')
            vsize = self.unpack(physical, addr + 0x8, 4)
            vaddr = self.unpack(physical, addr + 0xc, 4)
            psize = self.unpack(physical, addr + 0x10, 4)
            paddr = self.unpack(physical, addr + 0x14, 4)
            char = self.unpack(physical, addr + 0x24, 4) # characteristics of a section
            flag = 0 # readable=0, writeable=1, executable=2, mrdata section = 3

            if char & IMAGE_SECTION_HEADER["MEM_EXECUTE"] > 0:
                flag = 2
            if char & IMAGE_SECTION_HEADER["MEM_WRITE"] > 0:
                flag = 1
            if '.mrdata' in name:
                flag = 3
            sections.append([vsize, vaddr, psize, paddr, flag])
        return sections

    def expand(self, physical, sections, header_size):
        """Build the virtual layout of the pe"""
        virtual = self.expand_header(physical, header_size)
        perms = [0 for x in range(len(virtual) // 0x1000)]
        prev_perm = 0 # permission of previous section
        for section in sections:
            vaddr = section[1]
            perms += [prev_perm for x in range((vaddr - len(virtual)) // 0x1000)]
            expanded, perm = self.expand_section(physical, section)
            perms += perm
            prev_perm = perm[0]
            virtual = self.append(virtual, expanded, vaddr)
        return virtual, perms

    def expand_header(self, physical, size):
        """Expand the header to take up a full page.
           If it takes less, it will be overwritten by a section"""
        virtual = physical[0:size]
        # pad to page boundary
        size = size + (0x1000 - (size % 0x1000))
        virtual = virtual.ljust(size, b'\x00')  # fast?
        return virtual

    def expand_section(self, physical, section):
        """Expand a section to take up its virtual size"""
        vsize, vaddr, psize, paddr, perm = section

        expanded = physical[paddr:paddr + min(vsize, psize)]
        expanded = expanded.ljust(vsize, b'\x00')  # how fast is this?

        size = len(expanded)
        # pad out to a multiple of the page size (4k)
        if size % 0x1000 != 0:
            size = size + (0x1000 - (size % 0x1000))
            expanded = expanded.ljust(size, b'\x00')  # how fast is this?
        perms = [perm for x in range(size // 0x1000)]
        return expanded, perms

    def append(self, virtual, expanded, vaddr):
        """Add (or replace) the new data at the specified vaddr"""
        if vaddr < len(virtual):
            virtual = virtual[:vaddr]
        elif vaddr > len(virtual):
            # pad
            virtual = virtual.ljust(vaddr, b'\x00')  # fast?
        virtual += expanded
        return virtual

    def parse_alterations(self, virtual, relocs, iat, other_alterations):
        """Parse for what addresses need to be normalised for this address"""
        reloc_zeroes = self.relocations(virtual, relocs)
        iat_zeroes = self.iat(iat)

        for alternation in other_alterations:
            alternation_zeroes = self.iat(alternation)
            iat_zeroes = {**iat_zeroes, **alternation_zeroes}

        # combine alterations
        alterations = {}
        vaddr = 0
        while vaddr < len(virtual):
            # test to see whether combining is required
            relocs_exist = vaddr in reloc_zeroes
            iat_exists = vaddr in iat_zeroes
            if relocs_exist and iat_exists:
                # assumption - these alterations will never overlap
                alterations[vaddr] = reloc_zeroes[vaddr] + iat_zeroes[vaddr]
                alterations[vaddr] = list(set(alterations[vaddr]))
                alterations[vaddr].sort()
            elif relocs_exist:
                alterations[vaddr] = reloc_zeroes[vaddr]
            elif iat_exists:
                alterations[vaddr] = iat_zeroes[vaddr]
            vaddr += 0x1000
        return alterations

    def relocations(self, virtual, reloc_table):
        """Get all the relocations for the pe, broken into chunks based on pages"""
        addr = reloc_table[0]
        reloc_size = reloc_table[1]
        relocs = virtual[addr:addr + reloc_size]
        # IMAGE_BASE_RELOCATION
        offset = 0
        zeroes = {}
        while offset < reloc_size:
            vaddr = self.unpack(relocs, offset, 4)
            size = self.unpack(relocs, offset + 0x4, 4)
            if size == 0:
                break
            page_relocs = relocs[offset + 0x8:offset + 0x8 + size]
            zeroes[vaddr] = self.parse_relocations(page_relocs)
            offset += size
        return zeroes

    def parse_relocations(self, relocs):
        """Parse the relocations for the given page"""
        zeroes = []
        offset = 0
        last = -1
        while offset < len(relocs):
            entry = self.unpack(relocs, offset, 2)
            reloc_type = (entry & 0xF000) >> 12
            reloc_addr = entry & 0x0FFF
            if reloc_type == 3:
                # IMAGE_REL_BASED_HIGHLOW
                if reloc_addr > last:
                    # prevent padding 0's from being added
                    zeroes.append(reloc_addr)
                    last = reloc_addr
            elif reloc_type == 0:
                # IMAGE_REL_BASED_ABSOLUTE - used as padding
                pass
            elif reloc_type == 10:
                if reloc_addr > last and (reloc_addr + 4) > last:
                    zeroes.append(reloc_addr)
                    zeroes.append(reloc_addr + 4)
                    last = reloc_addr + 4
            else:
                # TODO - any other types (not yet encountered)
                pass
            offset += 0x2
        return zeroes

    def iat(self, iat):
        """Determine where to normalise the import address table"""
        base_addr = iat[0]
        size = iat[1]
        zeroes = {}
        # work out what page to save the information to
        offset = base_addr % 0x1000
        addr = base_addr - (offset)
        zeroes[addr] = []
        while addr + offset < base_addr + size:
            if offset == 0x1000:
                # move to the next page
                addr += offset
                zeroes[addr] = []
                offset = 0
            zeroes[addr].append(offset)
            offset += 4
        return zeroes

    def zero(self, virtual, alterations):
        """Normalise the alterations and split into page size chunks"""
        vaddr = 0
        pages = {}
        unapplied = 0
        while vaddr < len(virtual):
            if vaddr in alterations:
                zeroes = alterations[vaddr]
                offset = 0
                # check for any unapplied zeroes from page overlaps
                if unapplied > 0:
                    data = b'\x00' * unapplied
                    offset = unapplied
                    # add position of where alteration would start
                    alterations[vaddr].insert(0, -(4 - unapplied))
                    unapplied = 0
                else:
                    data = bytearray()
                for zero in zeroes:
                    if zero < 0 or zero < offset:
                        # already been applied or padding
                        continue
                    # add previous
                    data += virtual[vaddr + offset:vaddr + zero]
                    # add zeroes
                    if zero <= 0x1000 - 4:
                        # does not cross page boundary
                        data += b'\x00\x00\x00\x00'
                        offset = zero + 4
                    else:
                        # crosses page boundary
                        diff = 0x1000 - zero
                        data += b'\x00' * diff
                        unapplied = 4 - diff
                        offset = 0x1000
                # add remaining
                if offset < 0x1000:
                    data += virtual[vaddr + offset:vaddr + 0x1000]
                pages[vaddr] = data
            else:
                pages[vaddr] = virtual[vaddr:vaddr + 0x1000]
            vaddr += 0x1000
        return pages, alterations

    def unpack(self, data, offset, length):
        """Unpack the string into a value"""
        string = data[offset:offset + length]
        if length == 4:
            return struct.unpack("<L", string)[0]
        elif length == 2:
            return struct.unpack("H", string)[0]
        elif length == 8:
            return struct.unpack("Q", string)[0]
        else:
            print("Error, unknown type - length {0}".format(len(string)))
            exit()

    def hash(self, pages):
        """Hash the normalised pages"""
        hashes = {}
        for addr, page in pages.items():
            hash = hashlib.sha256(page).hexdigest()
            hashes[addr] = hash
        return hashes

    def output(self, hashes, zeroes, perms, path, name):
        """Output the hash information to a file"""
        output = []
        offset = 0
        while offset / 0x1000 < len(hashes):
            hash = hashes[offset]
            #filename, index, hash value, permission (readable=0, writeable=1, executable=2), zeroed addresses
            line = "{0},{1},{2},{3},{4}\n"
            if offset in zeroes:
                offsets = ["{0}".format(x) for x in zeroes[offset]]
                offsets = " ".join(offsets)
            else:
                offsets = ""
            output.append(line.format(name, offset // 0x1000, hash, perms[offset // 0x1000], offsets))
            offset += 0x1000
        print("Hashed ", path)
        return output

    def filter(self, output):
        """Remove duplicate entries"""
        # combine hashes from all files into a single list
        # zip different length lists - http://docs.python.org/2/library/itertools.html#itertools.izip_longest
        # zip lists into single list - http://stackoverflow.com/questions/3471999/how-do-i-merge-two-lists-into-a-single-list
        # zip unknown number of lists - http://stackoverflow.com/questions/5938786/how-would-you-zip-an-unknown-number-of-lists-in-python
        output = itertools.izip_longest(*output)
        output = list(itertools.chain.from_iterable(output))

        # remove duplicates
        # from http://stackoverflow.com/questions/480214/how-do-you-remove-duplicates-from-a-list-in-python-whilst-preserving-order
        seen = set()
        seen_add = seen.add
        output = [x for x in output if x not in seen and not seen_add(x)]

        # remove None added by using izip_longest with different length lists
        if None in output:
            output.remove(None)
        return output

if __name__ == "__main__":
    hashes = HashBuild(sys.argv)
