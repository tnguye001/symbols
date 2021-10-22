#   Hashbuild
#   Create hashes from ELF files by implementing a custom ELF loader and linker


import sys
import struct
import hashlib
import itertools
import os
import os.path


Segment_Permissions = {
    "PF_R": 0x4, # Readable
    "PF_W": 0x2, # Writable
    "PF_X": 0x1, # Executable
}

Segment_Type = {
    "PT_NULL":    0x0,  # Program header table entry unused
    "PT_LOAD":    0x1,  # Loadable segment
    "PT_DYNAMIC": 0x2,  # Dynamic linking information
    "PT_INTERP":  0x3,  # Interpreter information
    "PT_NOTE":    0x4,  # Auxiliary information
    "PT_SHLIB":   0x5,  # reserved
    "PT_PHDR":    0x6,  # segment containing program header table itself
    "PT_TLS":     0x7,  # Thread-Local Storage template
    "PT_GNU_EH_FRAME": 0x6474e550,  # Exception Handling information
    "PT_GNU_STACK":    0x6474e551,  # Stack flags
    "PT_GNU_RELRO":    0x6474e552,  # Read only after relocation
    "PT_GNU_PROPERTY": 0x6474e553	# GNU property
}


Section_Type = {
    "SHT_SYMTAB":  0x2,  # Symbol table
    "SHT_STRTAB":  0x3,  # String table
    "SHT_RELA":    0x4,  # Relocation entries with addends
    "SHT_HASH":    0x5,  # Symbol hash table
    "SHT_DYNAMIC": 0x6,  # Dynamic linking information
    "SHT_NOTE":    0x7,  # Notes
    "SHT_NOBITS":  0x8,  # Program space with no data (bss)
    "SHT_REL":     0x9,  # Relocation entries, no addends
    "SHT_SHLIB":   0x0A, # Reserved
    "SHT_DYNSYM":  0x0B, # Dynamic linker symbol table
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
        """Find all ELF files on disk"""
        pass


# ----------------------
# Module Implementations
# ----------------------
class Filesystem(Disk):
    """Read files from a mounted disk image"""

    def __init__(self, disk):
        super(Filesystem, self).__init__(disk)

    def read(self, path):
        """Read all ELF files on disk"""
        f = open(path, "rb")
        data = f.read()
        f.close()
        return data

    def find(self):
        """Find all ELF files on disk"""
        extensions = [".axf", ".bin", ".o", ".elf", ".prx", ".puff", ".ko", ".mod", ".so"]
        for path, dirs, files in os.walk(self.disk):
            for filename in files:
                name = filename.lower()
          #      for extension in extensions:
          #          if extension in name or "." not in name:
                yield name, os.path.join(path, filename)
          #              break


# ----------
# Main Logic
# ----------
class HashBuild:
    "Build a hash for each ELF file on the disk"

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

        # parse ELFs and build hashes
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
        """Process the ELF file and return the hash output"""
        # determine the information required for building the virtual layout
        data = self.parse(physical)
        if not (data):
            if physical != None and len(physical) > 0:
                print("Error - ", path + " " + name)
            else:
                print("Error - ", path + name, " - 0 length")
            return []
        file_header_size, segments, sections = data
        # build the virtual layout
        virtual, perms = self.expand(physical, segments)

        # determine which values need to be zeroed

        alterations = self.parse_alterations(physical, virtual, sections)
        # apply the normalisation and split into pages
        pages, zeroes = self.zero(virtual, alterations)
        # hash
        hashes = self.hash(pages)
        return hashes, zeroes, virtual, perms

    def parse(self, physical):
        """Retrieve all necessary details from the ELF to allow expansion"""
        data = self.parse_header(physical)
        if data == None:
            # error
            return None
        if len(data) != 4:
            return None
        file_header_size, segments_info, sections_info, names_section_index = data
        segment_header_table_address, num_segment_headers, segment_header_size = segments_info
        section_header_table_address, num_section_headers, section_header_size = sections_info

        sections = self.parse_sections(physical, section_header_table_address, num_section_headers, section_header_size, names_section_index)

        segments = self.parse_segements(physical, segment_header_table_address, num_segment_headers,segment_header_size)
        return file_header_size, segments, sections


    def parse_header(self, physical):
        """Parse the header and return required values"""
        # _IMAGE_DOS_HEADER
        if not (physical):
            return None
        encoding = 'utf-8'
        if physical[0:4] != bytearray(b'\x7F\x45\x4C\x46'): # 0x7FELF Magic number for ELF file
            print("Error, invalid ELF header")
            return None

        EI_CLASS = self.unpack(physical, 4, 1)
        if EI_CLASS == 1:  #ELF 32-bit
            self.is32 = True
            num_section_headers = self.unpack(physical, 0x30, 2) # e_shnum
            section_header_size = self.unpack(physical,0x2E, 2)  # e_shentsize
            sections_header_table_address = self.unpack(physical, 0x20, 4)   # e_shoff
            sections_header_table = physical[sections_header_table_address:sections_header_table_address + section_header_size * num_section_headers]

            num_segment_headers = self.unpack(physical, 0x2C, 2)  # e_phnum
            segment_header_size = self.unpack(physical, 0x2A, 2)  # e_phentsize
            segment_header_table_address = self.unpack(physical, 0x1C, 4)  # e_phoff
            segments_header_table = physical[
                                    segment_header_table_address:segment_header_table_address + segment_header_size * num_segment_headers]
            names_section_index = self.unpack(physical, 0x32, 2)

            file_header_size = 52
            return file_header_size, (segment_header_table_address,num_segment_headers,segment_header_size), (sections_header_table_address, num_section_headers, section_header_size), names_section_index

        elif EI_CLASS == 2:  #ELF 64-bit
            self.is32 = False
            # _IMAGE_FILE_HEADER
            num_section_headers = self.unpack(physical, 0x3C, 2) # e_shnum
            section_header_size = self.unpack(physical,0x3A, 2)  # e_shentsize
            sections_header_table_address = self.unpack(physical, 0x28, 8)   # e_shoff
            sections_header_table = physical[sections_header_table_address:sections_header_table_address + section_header_size * num_section_headers]

            num_segment_headers = self.unpack(physical, 0x38, 2)  # e_phnum
            segment_header_size = self.unpack(physical, 0x36, 2)  # e_phentsize
            segment_header_table_address = self.unpack(physical, 0x20, 8)  # e_phoff
            segments_header_table = physical[
                                    segment_header_table_address:segment_header_table_address + segment_header_size * num_segment_headers]
            names_section_index = self.unpack(physical, 0x3E, 2)

            file_header_size = 64
            return file_header_size, (segment_header_table_address,num_segment_headers,segment_header_size), (sections_header_table_address, num_section_headers, section_header_size), names_section_index

        else:
            print("Not a 32-bit/64-bit ELF")
            return None

    def reloc_sections(self, sections):
        """Search for the relocation sections and send back their info"""
        reloc_sections = []
        for section in sections:
            section_type = section[3]
            # ela.dyn and .rela.plt usually include addresses to be changed in .init.array, .fini_array .got
            if section_type == Section_Type["SHT_RELA"] or section_type == Section_Type["SHT_REL"]:
                reloc_sections.append(section)
        return reloc_sections

    def linker_symbol_sections(self, sections):
        """Search for the Dynamic linker symbol table sections and send back their info"""
        dyn_symbol_sections = []
        for section in sections:
            section_type = section[3]
            if section_type == Section_Type["SHT_DYNSYM"]:
                dyn_symbol_sections.append(section)
        return dyn_symbol_sections

    def dynamic_sections(self, sections):
        """Search for the Dynamic sections send back their info"""
        dynamic_sections = []
        for section in sections:
            section_type = section[3]
            section_name = section[4]
            if section_type == Section_Type["SHT_DYNAMIC"] or section_name == '.data.rel.ro':
                dynamic_sections.append(section)
        return dynamic_sections

    def parse_directory(self, data, offset):
        """Convert a single directory entry into a pair of rva / size values"""
        vaddr = self.unpack(data, offset + 0x0, 4)
        size = self.unpack(data, offset + 0x4, 4)
        return vaddr, size

    # parse the segements and add the suitable permissions to segements information
    def parse_segements(self, physical, segments_header_table_address, num_segment_headers, segment_header_size):
        """Parse the details of each section - IMAGE_SECTION_HEADER"""
        segments = []
        for i in range(num_segment_headers):
            addr = segments_header_table_address + i * segment_header_size
            if self.is32:
                paddr = self.unpack(physical, addr + 0x04, 4)  #p_offset
                vaddr = self.unpack(physical, addr + 0x08, 4)  #p_vaddr
                psize = self.unpack(physical, addr + 0x10, 4)  #p_filesz
                vsize = self.unpack(physical, addr + 0x14, 4) #p_memsz
                type = self.unpack(physical, addr + 0, 4) #p_type
                p_flags = self.unpack(physical, addr + 0x18, 4) #p_flags : characteristics of a section

            else:
                paddr = self.unpack(physical, addr + 0x08, 8) #p_offset
                vaddr = self.unpack(physical, addr + 0x10, 8) #p_vaddr
                psize = self.unpack(physical, addr + 0x20, 8) #p_filesz
                vsize = self.unpack(physical, addr + 0x28, 8) #p_memsz
                type = self.unpack(physical, addr + 0, 4)  # p_type
                p_flags = self.unpack(physical, addr + 0x04, 4) #p_flags : characteristics of a section

            perm = 0  # readable=0, writeable=1, executable=2
            if p_flags & Segment_Permissions["PF_X"] > 0:
                perm = 2
            if p_flags & Segment_Permissions["PF_W"] > 0:
                perm = 1
            segments.append([vsize, vaddr, psize, paddr, perm, type])
        return segments



    def get_section_name(self,names, offset):

        i = offset
        name = bytearray()
        while names[i] != 0:
            a = names[i]
            name.append(names[i])
            i += 1

        return name.decode('ascii')

    # parse the sections
    def parse_sections(self, physical, sections_header_table_address, num_section_headers, section_header_size, names_section_index):
        """Parse the details of each section - IMAGE_SECTION_HEADER"""

        names_section_addr = sections_header_table_address + names_section_index * section_header_size
        if self.is32:
            paddr = self.unpack(physical, names_section_addr + 0x10, 4)
            psize = self.unpack(physical, names_section_addr + 0x14, 4)
        else:
            paddr = self.unpack(physical, names_section_addr + 0x18, 8)
            psize = self.unpack(physical, names_section_addr + 0x20, 8)
            names = physical[paddr:paddr + psize]


        sections = []
        for i in range(num_section_headers):
            addr = sections_header_table_address + i * section_header_size
            if self.is32:
                paddr = self.unpack(physical, addr + 0x10, 4)  #sh_offset
                vaddr = self.unpack(physical, addr + 0x0C, 4)  #sh_addr
                psize = self.unpack(physical, addr + 0x14, 4)  #sh_size
                type = self.unpack(physical, addr + 0x04, 4) #sh_type : characteristics of a section
                name_offset = self.unpack(physical, addr, 4) # offset to a string in the String table (.shstrtab section)
                name = self.get_section_name(names, name_offset)
            else:
                paddr = self.unpack(physical, addr + 0x18, 8)  #sh_offset
                vaddr = self.unpack(physical, addr + 0x10, 8)  #sh_addr
                psize = self.unpack(physical, addr + 0x20, 8)  #sh_size
                type = self.unpack(physical, addr + 0x04, 4) #sh_flags : characteristics of a section
                name_offset = self.unpack(physical, addr, 4) # offset to a string in the String table (.shstrtab section)
                name = self.get_section_name(names, name_offset)

            sections.append([vaddr, psize, paddr, type, name]) # vaddr, psize, paddr, type, name

        return sections

    # vsize, vaddr, psize, paddr, perm, type
    def expand(self, physical, segments):
        """Build the virtual layout of the ELF"""
        virtual = bytearray()
        perms = []
  #      virtual = self.expand_header(physical, header_size)
  #      perms = [0 for x in range(len(virtual) // 0x1000)]
        prev_perm = -1 # permission of previous section
        #sorting segments according to vaddr

        for segment in segments:
            if segment[5] == (Segment_Type["PT_LOAD"] and  segment[4] != 1) or (segment[5] == Segment_Type["PT_GNU_RELRO"]):
                vsize, vaddr, psize, paddr, perm, type = segment

                perms += [prev_perm for x in range((vaddr - len(virtual)) // 0x1000)]
                expanded, perm = self.expand_segment(physical, segment)
                perms += perm
                if len(perm) > 0 and len(expanded) > 0:
                    prev_perm = perm[0]
                    virtual = self.append(virtual, expanded, vaddr - vaddr % 0x1000)

        return virtual, perms

    def expand_header(self, physical, size):
        """Expand the header to take up a full page.
           If it takes less, it will be overwritten by a section"""
        virtual = physical[0:size]
        # pad to page boundary
        size = size + (0x1000 - (size % 0x1000))
        virtual = virtual.ljust(size, b'\x00')  # fast?
        return virtual


    #vsize, vaddr, psize, paddr, flag
    def expand_segment(self, physical, segment):
        """Expand a section to take up its virtual size"""
        vsize, vaddr, psize, paddr, perm, type = segment

        size = vsize + (0x1000 - (vsize % 0x1000))
        expanded = physical[paddr:paddr + size] # The Linux OS loader takes the rest of the bytes until 4K from the file
                                                # and does NOT pad with zeros! wierd huh?!
        start_addr = paddr - paddr % 0x1000
        size = vsize + (0x1000 - (vsize % 0x1000))
        expanded = physical[start_addr:start_addr + size]

        perms = [perm for x in range(size // 0x1000)]
        return expanded, perms

    def append(self, virtual, expanded, vaddr):
        """Add (or replace) the new data at the specified vaddr"""
        if vaddr < len(virtual):
            virtual = virtual[:vaddr]
        elif vaddr > len(virtual):
            # pad
            virtual = virtual.ljust(vaddr, b'\x00')
        virtual += expanded
        return virtual


    def parse_alterations(self, physical, virtual,sections):
        """Parse for what addresses need to be normalised for this address"""

        # reloc_sections: vaddr, psize, paddr, type, name_offset
        reloc_sections = self.reloc_sections(sections)
        reloc_zeroes = self.zero_relocations(physical, reloc_sections)

   #     linker_symbol_sections = self.linker_symbol_sections(sections) #IATs in PEs
      #  linker_symbol_zeroes = self.linker_symbols(linker_symbol_sections)

        dynamic_sections = self.dynamic_sections(sections)
        dynamic_sections_zeroes = self.dynamic_sections_zeroes(dynamic_sections)


        # combine alterations
        alterations = {}
        vaddr = 0
        while vaddr < len(virtual):
            # test to see whether combining is required
            relocs_exist = vaddr in reloc_zeroes
            dynamic_section = vaddr in dynamic_sections_zeroes
            if relocs_exist and dynamic_section:
                # assumption - these alterations will never overlap
                alterations[vaddr] = reloc_zeroes[vaddr] + dynamic_sections_zeroes[vaddr]
                alterations[vaddr] = list(set(alterations[vaddr]))
                alterations[vaddr].sort()
            elif relocs_exist:
                alterations[vaddr] = reloc_zeroes[vaddr]
            elif dynamic_section:
                alterations[vaddr] = dynamic_sections_zeroes[vaddr]
            vaddr += 0x1000
        return alterations

    def zero_relocations(self, physical, reloc_sections):
        """Get all the relocations for the ELF, broken into chunks based on pages"""
        zeroes = {}
        # reloc_section: [vaddr, psize, paddr, type]
        for reloc_section in reloc_sections:
            offset = 0
            if self.is32:
                address_size = 4
                if reloc_section[3] == Section_Type["SHT_REL"]:
                    entry_size = 8
                else:
                    entry_size = 12
            else:
                address_size = 8
                if reloc_section[3] == Section_Type["SHT_REL"]:
                    entry_size = 16
                else:
                    entry_size = 24

            while offset < reloc_section[1]:
                reloc_addr = self.unpack(physical, reloc_section[2] + offset, address_size)
                reloc_addr_base = reloc_addr - (reloc_addr % 0x1000) # Virtual address of base of the page where reloc_addr exists
                zeroes.setdefault(reloc_addr_base, []).append(reloc_addr-reloc_addr_base)
                if not self.is32 and (reloc_addr // 0x1000 == (reloc_addr+4) // 0x1000):
                    zeroes.setdefault(reloc_addr_base, []).append(reloc_addr+4-reloc_addr_base)
                offset += entry_size

        return zeroes


#TODO: modify this functions and check if it's needed
    def linker_symbols(self, linker_symbol_sections):
        """Determine where to normalise the import/export address table"""
        zeroes = {}
        return zeroes
        # linker_symbol_section: [vaddr, psize, paddr, type]
        for linker_symbol_section in linker_symbol_sections:
            if self.is32: # Elf32_Sym struct size
                address_size = 4
                entry_size = 16
            else: # Elf64_Sym struct size
                address_size = 8
                entry_size = 28
            offset = 0

            while offset < reloc_section[1]:
                reloc_addr = self.unpack(physical, reloc_section[2] + offset, address_size)
                reloc_addr_base = reloc_addr - (
                            reloc_addr % 0x1000)  # Virtual address of base of the page where reloc_addr exists
                zeroes.setdefault(reloc_addr_base, []).append(reloc_addr)
                if not self.is32 and (reloc_addr // 0x1000 == (reloc_addr + 4) // 0x1000):
                    zeroes.setdefault(reloc_addr_base, []).append(reloc_addr + 4)
                offset += entry_size

            return zeroes

    def dynamic_sections_zeroes(self, dynamic_sections):
        # dynamic_sections: [vaddr, psize, paddr, type]
        zeroes = {}

        for dynamic_section in dynamic_sections:
            offset = 0
            vaddr, psize, paddr, type, section_name = dynamic_section
            while offset < psize:
                reloc_addr = vaddr + offset
                reloc_addr_base = reloc_addr - (reloc_addr % 0x1000)  # Virtual address of base of the page where reloc_addr exists
                zeroes.setdefault(reloc_addr_base, []).append(reloc_addr - reloc_addr_base)
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
                    # add position of where alterati on would start
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
        if length == 1:
            return struct.unpack("B", string)[0]
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
                # convert offsets to hex
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