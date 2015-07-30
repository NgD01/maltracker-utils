# This file is part of 
# Maltracker - Malware analysis and tracking platform
# http://www.maltracker.net
# http://www.anubisnetworks.com
#
# Copyright (C) 2014-2015 AnubisNetworks, NSEC S.A.
# Copyright (C) 2013-2014 Valter Santos.
# See the file 'docs/LICENSE' for copying permission.

from __future__ import division

import os
import sys
import hashlib
import binascii
import magic
import pydeep
import pefile
import base64
import bitstring
import string
import bz2
import hashlib
import re
from datetime import datetime

try:
    import yara
    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

class File:
    def __init__(self, file_path=None, file_data=None, base64_encoded=False, rules_path=None):
        self.file_path = file_path
        self.base64_encoded = base64_encoded
        self.rules_path = rules_path

        if file_path:
            self.file_data = open(self.file_path, "rb").read()
        else:
            if base64_encoded:
                self.file_data = base64.b64decode(file_data)
            else:
                self.file_data = file_data

    def as_dict(self, exclude=None):
        ret = {
                "name": self.get_name() if 'name' not in exclude else None,
                "size": self.get_size() if 'size' not in exclude else None,
                "crc32": self.get_crc32() if 'crc32' not in exclude else None,
                "type": self.get_type() if 'type' not in exclude else None,
                "md5": self.get_md5() if 'md5' not in exclude else None,
                "sha1": self.get_sha1() if 'sha1' not in exclude else None,
                "sha256": self.get_sha256() if 'sha256' not in exclude else None,
                "sha512": self.get_sha512() if 'sha512' not in exclude else None,
                "ssdeep": self.get_ssdeep() if 'ssdeep' not in exclude else None,
                "imphash": self.get_imphash() if 'imphash' not in exclude else None,
                "pehash": self.get_pehash() if 'pehash' not in exclude else None,
                "data": self.get_data(base64_encoded=True)  if 'data' not in exclude else None,
                "strings": self.get_strings() if 'strings' not in exclude else None,
                "yara": self.get_yara() if 'yara' not in exclude else None,
            }

        return ret

    def store(self, file_path=None): 
        
        if not self.file_path:
            self.file_path = file_path

        try:
            dlfile = open(file_path, "wb")
            dlfile.write(self.get_data())
            dlfile.close()
            return True
        except:
            return False


    def get_name(self):
        file_name = os.path.basename(self.file_path)
        return file_name

    def get_data(self, base64_encoded=False):
        if base64_encoded:
            try:
                return base64.b64decode(self.file_data)
            except:
                return self.file_data
        else:
            return self.file_data

    def get_strings(self):
        return re.findall("[\x1f-\x7e]{6,}", self.file_data)


    def get_size(self):
        return len(self.file_data)

    def get_crc32(self):
        res = ''
        crc = binascii.crc32(self.file_data)
        for i in range(4):
            t = crc & 0xFF
            crc >>= 8
            res = '%02X%s' % (t, res)
        return res

    def get_md5(self):
        return hashlib.md5(self.file_data).hexdigest()

    def get_sha1(self):
        return hashlib.sha1(self.file_data).hexdigest()

    def get_sha256(self):
        return hashlib.sha256(self.file_data).hexdigest()

    def get_sha512(self):
        return hashlib.sha512(self.file_data).hexdigest()

    def get_ssdeep(self):
        try:
            return pydeep.hash_file(self.file_path)
        except Exception:
            return None

    def get_imphash(self, is_pe=False):

        try:
            retval = None
            if is_pe or "PE32" in self.get_type():
                pe = pefile.PE(self.file_path)
                retval = pe.get_imphash()
            return retval

        except Exception:
            return None


    def get_timestamp(self, is_pe=False):

        try:
            retval = None
            if is_pe or "PE32" in self.get_type():
                pe = pefile.PE(self.file_path)
                pe_timestamp = pe.FILE_HEADER.TimeDateStamp
                retval = datetime.fromtimestamp(pe_timestamp).strftime("%Y-%m-%d %H:%M:%S")

            return retval

        except Exception:
            return None


    def get_type(self):
        try:
            ms = magic.open(magic.MAGIC_NONE)
            ms.load()
            file_type = ms.buffer(self.file_data)
        except:
            try:
                file_type = magic.from_buffer(self.file_data)
            except:
                try:
                    import subprocess
                    file_process = subprocess.Popen(['file', '-b', self.file_path], stdout = subprocess.PIPE)
                    file_type = file_process.stdout.read().strip()
                except:
                    return None

        return file_type


    def get_pehash(self, is_pe=False):
        """ get_pehash(): returns the pehash of file_path
            pehash refs:
                https://www.usenix.org/legacy/event/leet09/tech/full_papers/wicherski/wicherski.pdf
                http://totalhash.com/blog/pehash-source-code/
        """ 

        try:
            retval = None

            if is_pe or "PE32" in self.get_type():
                exe = pefile.PE(self.file_path)

                #image characteristics
                img_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Characteristics))
                #pad to 16 bits
                img_chars = bitstring.BitArray(bytes=img_chars.tobytes())
                img_chars_xor = img_chars[0:7] ^ img_chars[8:15]

                #start to build pehash
                pehash_bin = bitstring.BitArray(img_chars_xor)

                #subsystem - 
                sub_chars = bitstring.BitArray(hex(exe.FILE_HEADER.Machine))
                #pad to 16 bits
                sub_chars = bitstring.BitArray(bytes=sub_chars.tobytes())
                sub_chars_xor = sub_chars[0:7] ^ sub_chars[8:15]
                pehash_bin.append(sub_chars_xor)

                #Stack Commit Size
                stk_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfStackCommit))
                stk_size_bits = string.zfill(stk_size.bin, 32)
                #now xor the bits
                stk_size = bitstring.BitArray(bin=stk_size_bits)
                stk_size_xor = stk_size[8:15] ^ stk_size[16:23] ^ stk_size[24:31]
                #pad to 8 bits
                stk_size_xor = bitstring.BitArray(bytes=stk_size_xor.tobytes())
                pehash_bin.append(stk_size_xor)

                #Heap Commit Size
                hp_size = bitstring.BitArray(hex(exe.OPTIONAL_HEADER.SizeOfHeapCommit))
                hp_size_bits = string.zfill(hp_size.bin, 32)
                #now xor the bits
                hp_size = bitstring.BitArray(bin=hp_size_bits)
                hp_size_xor = hp_size[8:15] ^ hp_size[16:23] ^ hp_size[24:31]
                #pad to 8 bits
                hp_size_xor = bitstring.BitArray(bytes=hp_size_xor.tobytes())
                pehash_bin.append(hp_size_xor)

                #Section chars
                for section in exe.sections:
                    #virutal address
                    sect_va =  bitstring.BitArray(hex(section.VirtualAddress))
                    sect_va = bitstring.BitArray(bytes=sect_va.tobytes())
                    pehash_bin.append(sect_va)    

                    #rawsize
                    sect_rs =  bitstring.BitArray(hex(section.SizeOfRawData))
                    sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
                    sect_rs_bits = string.zfill(sect_rs.bin, 32)
                    sect_rs = bitstring.BitArray(bin=sect_rs_bits)
                    sect_rs = bitstring.BitArray(bytes=sect_rs.tobytes())
                    sect_rs_bits = sect_rs[8:31]
                    pehash_bin.append(sect_rs_bits)

                    #section chars
                    sect_chars =  bitstring.BitArray(hex(section.Characteristics))
                    sect_chars = bitstring.BitArray(bytes=sect_chars.tobytes())
                    sect_chars_xor = sect_chars[16:23] ^ sect_chars[24:31]
                    pehash_bin.append(sect_chars_xor)

                    #entropy calulation
                    address = section.VirtualAddress
                    size = section.SizeOfRawData
                    raw = exe.write()[address+size:]
                    if size == 0: 
                        kolmog = bitstring.BitArray(float=1, length=32)
                        pehash_bin.append(kolmog[0:7])
                        continue
                    bz2_raw = bz2.compress(raw)
                    bz2_size = len(bz2_raw)
                    #k = round(bz2_size / size, 5)
                    k = bz2_size / size
                    kolmog = bitstring.BitArray(float=k, length=32)
                    pehash_bin.append(kolmog[0:7])

                m = hashlib.sha1()
                m.update(pehash_bin.tobytes())
                retval = m.hexdigest()

            return retval

        except Exception:
            return None



    def get_yara(self):
        """ Runs yara on the file and returns an array of yara rule hits
        """ 

        matches = list()

        if HAVE_YARA and self.rules_path:
            if os.path.getsize(self.file_path) > 0:
                try:
                    rules = yara.compile(self.rules_path)

                    for match in rules.match(self.file_path):
                        strings = []
                        for s in match.strings:
                            try:
                                new = s[2].encode("utf-8")
                            except UnicodeDecodeError:
                                s = s[2].lstrip("uU").encode("hex").upper()
                                s = " ".join(s[i:i+2] for i in range(0, len(s), 2))
                                new = "{ %s }" % s

                            if new not in strings:
                                strings.append(new)

                        matches.append({"name": match.rule,
                                        "meta": match.meta,
                                        "strings": strings})
                except yara.Error as e:
                    return None

        return matches        


    def get_package(self, file_type=None):
        """ check if file has a valid mimetype and is suitable for analysis
        """

        if not file_type:
            file_type = self.get_type()

        if "DLL" in file_type and self.file_path.endswith(".cpl"):
            return "cpl"
        elif "DLL" in file_type:
            return "dll"
        elif "PE32" in file_type or "MS-DOS" in file_type:
            return "exe"
        elif "PDF" in file_type:
            return "pdf"
        elif "Rich Text Format" in file_type or "Microsoft Office Word" in file_type or self.file_path.endswith(".docx"):
            return "doc"
        elif "Microsoft Office Excel" in file_type or "Microsoft Excel" in file_type or self.file_path.endswith(".xlsx"):
            return "xls"
        elif "Zip archive" in file_type:
            return "zip"
        elif "HTML" in file_type:
            return "html"
        else:
            return None
