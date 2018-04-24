import sys
import tarfile
import struct
import os
from crc16 import crc16xmodem
import string
import random
import argparse
from subprocess import check_output


def walklevel(some_dir, level=1):
    some_dir = some_dir.rstrip(os.path.sep)
    assert os.path.isdir(some_dir)
    num_sep = some_dir.count(os.path.sep)
    for root, dirs, files in os.walk(some_dir):
        yield root, dirs, files
        num_sep_this = root.count(os.path.sep)
        if num_sep + level <= num_sep_this:
            del dirs[:]

# doesn't compress in a way VRP wants, thus useless
def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename, "w:gz") as tar:
        subdirs = [x[0] for x in walklevel(source_dir)]
        subdirs = subdirs[1:]
        for subdir in subdirs:
            print 'Adding to tar %s | %s' % (subdir, os.path.basename(subdir))
            tar.add(subdir, arcname=os.path.basename(subdir))


def gen_id():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(7))


class Stream(object):
    @staticmethod
    def pck(data, size):
        if data is None:
            data = self.data
        try:
            s = {1: 'B', 2: '>H', 4: '>I'}[size]
        except:
            print 'Dont know how to pack; You fucked up with your code'
            exit(-1)
        try:
            return struct.pack(s, data)
        except struct.error:
            print 'Cant pack dat shit'
            return 0

    def unp(self, offset, size, data=None):
        if data is None:
            data = self.data
        try:
            s = {1: 'B', 2: '>H', 4: '>I'}[size]
        except:
            print 'Dont know how to unpack; You fucked up with your code'
            exit(-1)
        return struct.unpack(s, data[offset:offset + size])[0]

    def read(self, offset, size=0, data=None):
        if data is None:
            data = self.data
        if not size:
            return data[offset:]
        else:
            return data[offset:offset + size]


class HuaweiFirmware(Stream):
    def __init__(self, data):
        self.file_table = FileTable(data)

    def Gen(self):
        global object_types_str
        self.file_table.FixSelf()
        return self.file_table.Gen()


class FileTable(Stream):
    def __init__(self, data, object_type=None):
        self.data = data
        self.header1 = self.read(0, 2)
        self.crc16 = self.read(2, 2)
        self.header2 = self.read(4, 8)
        self.number_of_records = self.unp(0xc, 4)
        self.some_junk = self.read(0x10, 0x18)
        self.crc16_header = self.unp(0x182a, 2)
        self.file_records = []
        self.data = None
        self.header_padding_size = 0
        for i in range(self.number_of_records):
            self.file_records.append(FileRecord(data, 0x28 + i * 24))

    def FixSelf(self):
        # fix sizes and crcs

        self.header_padding_size = min(self.file_records, key=lambda x: x.start).start - (
            self.number_of_records * 24 + 0x28)

        for i in self.file_records:
            i.FixSelf()

        t = self.file_records
        t[0].start = 0x182c
        for i in range(1, len(t)):
            t[i - 1].padding_size = (t[i - 1].start + t[i - 1].size) % 8
            t[i].PrettyPrint()
            t[i].start = t[i - 1].start + t[i - 1].size + t[i - 1].padding_size



    def Gen(self):
        r = self.header2 + self.pck(self.number_of_records, 4) + self.some_junk
        k = ''
        for i in self.file_records:
            t = i.Gen()
            r += t[0]
            k += t[1]
        data = r + '\x00' * (self.header_padding_size-2)
        self.crc16_header = crc16xmodem(data[:-2])
        data += self.pck(self.crc16_header, 2) + k
        return self.header1 + self.pck(crc16xmodem(data), 2) + data


class TarFile(Stream):
    def __init__(self, data, object_type=None):
        self.data = data
        self.foobar = self.read(0, 6)
        self.crc16 = self.unp(6, 2)
        self.foobar2 = self.read(8, 4)  # 01 68 01 01
        self.foobar3 = self.read(0xc, 4)  # 00 01 00 00
        self.foobar4 = self.read(0x10, 0xc)  # 00 00 00 01 01 68 01 01 00 00 00 00
        self.size = self.unp(0x1c, 4)
        self.foobar5 = self.read(0x20, 4)  # 00 00 00 00
        self.filename = self.read(0x24, 0x20).replace('\x00', '')
        self.location = self.read(0x44, 0x93c)
        self.object = File(self.data[0x980:])
        self.obj_size = 0


    def FixSelf(self):
        self.object.FixSelf()
        self.filename = self.filename + '\x00' * (0x20 - len(self.filename))
        self.obj_size = 0x980 + self.object.obj_size
        self.size = self.object.size
        self.crc16 = crc16xmodem(self.foobar2 + self.foobar3 + \
                self.foobar4 + self.pck(self.size, 4) + self.foobar5 + \
                    self.filename + self.location + self.object.Gen()[:0x180])


    def Gen(self):
        r = self.foobar + self.pck(self.crc16, 2) + self.foobar2 + self.foobar3 + \
                self.foobar4 + self.pck(self.size, 4) + self.foobar5 + \
                    self.filename + self.location + self.object.Gen()
        return r


class File(Stream):
    def __init__(self, data, object_type=None):
        global file_types, str_file_types
        self.data = data
        self.foobar = self.read(0, 8)
        self.type = self.unp(8, 2)
        self.foobar2 = self.read(0xa, 0x8a)
        self.filename = self.read(0x94, 0xe0).replace('\x00', '')
        self.size = self.unp(0x174, 4)
        self.junk = self.read(0x178, 2)
        self.crc16 = self.unp(0x17a, 2)
        self.junk2 = self.read(0x17c, 4)
        self.data = self.read(0x180, self.size)
        self.obj_size = 0
        try:
            self.object = file_types[object_type](self.data)
        except KeyError:
            self.object = BinaryBlob(self.data)


        if self.crc16 != crc16xmodem(self.data):
            print 'Meh, CRC is wrong!'
            exit(0)

    def FixSelf(self):
        self.object.FixSelf()
        self.crc16 = crc16xmodem(self.object.Gen())
        self.size = self.object.obj_size
        self.obj_size = 0x180 + self.size
        self.filename = self.filename + '\x00' * (0xe0 - len(self.filename))

    def Gen(self):
        r = self.foobar + self.pck(self.type, 2) + self.foobar2 + self.filename + self.pck(self.size, 4) + self.junk \
            + self.pck(self.crc16, 2) + self.junk2 + self.object.Gen()
        return r


class BinaryBlob(Stream):
    def __init__(self, data, object_type=None):
        self.data = data
        self.obj_size = len(self.data)

    def FixSelf(self):
        self.obj_size = len(self.data)

    def Gen(self):
        return self.data


class FileRecord(Stream):
    def __init__(self, data, offset):
        global object_types, object_types_str

        self.data = data[offset:]
        self.minor_object_type = self.unp(0, 2)
        self.foobar = self.read(2, 2)
        self.start = self.unp(4, 4)
        self.size = self.unp(8, 4)
        self.some_flag = self.unp(0xc, 2)
        self.crc16 = self.unp(0xe, 2)
        self.major_object_type = self.unp(0x10, 4)
        self.foobar2 = self.read(0x14, 4)
        self.data = None
        self.padding_size = 0
        self.object = object_types[self.major_object_type](data[self.start:self.start + self.size], self.minor_object_type)

    def PrettyPrint(self):
        global object_types_str

        if object_types_str[self.major_object_type] == 'File':
            pass
        elif object_types_str[self.major_object_type] == 'FileTable':
            t = 0x28 + self.object.number_of_records * 24
            t += self.object.header_padding_size
            # plus sizes of all files
            for i in self.object.file_records:
                t += i.size
        elif object_types_str[self.major_object_type] == 'BinaryBlob':
            pass

    def FixSelf(self):
        global object_types_str

        self.object.FixSelf()

        ot = object_types_str[self.major_object_type]
        if ot == 'File':
            self.size = self.object.obj_size#len(self.object.data) + 0x180
            self.crc16 = self.object.crc16#crc16xmodem(self.data[0x180:]) # TODO: FIX CRC FOR ALL TYPE OF FILES
            self.object.crc16 = self.crc16

        elif ot == 'BinaryBlob':
            self.size = self.object.obj_size#len(self.object.data)

        elif ot == 'FileTable':
            self.size = 0x28 + self.object.number_of_records * 24
            self.size += self.object.header_padding_size
            # plus sizes of all files
            for i in self.object.file_records:
                self.size += i.size + i.padding_size

    def Gen(self):
        self.PrettyPrint()
        file_record = self.pck(self.minor_object_type, 2) + self.foobar + self.pck(self.start, 4) \
                      + self.pck(self.size, 4) + self.pck(self.some_flag,2) + self.pck(self.crc16, 2) + \
                        self.pck(self.major_object_type, 4) + self.foobar2
        _object = self.object.Gen() + '\x00' * self.padding_size
        return [file_record, _object]

file_types = {
    0x810e: TarFile
}

file_types_str = {
    0x810e: 'TarFile'
}


def FindFilesWithGivenName(object, name, level=0, verbose=False):
    results = []
    t = str(type(object))
    n = ''
    try:
        n = object.filename.replace('\x00', '').replace('\n', '').replace('\r', '')
    except:
        pass

    if ".FileTable'" in t:
        if verbose:
            print '%s ------ FILETABLE ------' % ('\t' * level)
        for i in object.file_records:
            results += FindFilesWithGivenName(i.object, name, level+1, verbose=verbose)

    # for both TarFile and File
    elif "File'" in t:
        results += FindFilesWithGivenName(object.object, name, level+1, verbose=verbose)
        prettyName = object.filename.replace('\x00', '').replace('\n', '').replace('\r', '')
        if verbose:
            pass
            print '%s "%s"' % ('\t' * level, prettyName)
        if name == prettyName:
            results.append(object)

    else:
        pass

    return results


def GetPathForObject(cur_object, object):
    if 'FileTable' in str(type(cur_object)):
        path = ['File Table of %i records' % cur_object.number_of_records]
        for i in cur_object.file_records:
            t = GetPathForObject(i.object, object)
            if t != []:
                return path + t

    try:
        path = [cur_object.filename]
    except AttributeError:
        return []

    if cur_object == object:
        return path
    t = GetPathForObject(cur_object.object, object)
    if t != []:
        return path+t
    else:
        return []

def PrettyPrintPath(path):
    r = ''
    for i in path:
        r += '[%s] --> ' % i
    return r[:-len(' --> ')]


object_types = {
    65536: File,
    65606: File,
    196617: File,
    65542: File,
    196616: File,
    7: FileTable,
    0: File,
    1: FileTable,
    196615: File,
    65537: File,
    65541: File,
    65544: File,
    60: File,
    61: File,
    1179048851: BinaryBlob,
    1162279811: BinaryBlob,
    38: BinaryBlob,
    48: BinaryBlob
}

object_types_str = {
    65536: 'File',
    65606: 'File',
    196617: 'File',
    65542: 'File',
    196616: 'File',
    7: 'FileTable',
    0: 'File',
    1: 'FileTable',
    196615: 'File',
    65537: 'File',
    65541: 'File',
    65544: 'File',
    60: 'File',
    61: 'File',
    1179048851: 'BinaryBlob',
    1162279811: 'BinaryBlob',
    38: 'BinaryBlob',
    48: 'BinaryBlob'
}

parser = argparse.ArgumentParser(description='Huawei firmware toolkit')
parser.add_argument('firmware', help='Path to firmware to mess with')
parser.add_argument('-filename', action='append', help='Name of file in the firmware filesystem to be replaced')
parser.add_argument('-replacement', action='append', help='Path to file containing new content of replaced file')
parser.add_argument('-type', action='append', help='Type of payload: bin, tar.gz, lzma. Default is plain bin')
parser.add_argument('-extract', action='append', help='Filename to be extracted')
parser.add_argument('-list', action='store_true', help='Just show which files are in firmware')
args = parser.parse_args()

if not args.list and not args.extract:
    if len(args.replacement) != len(args.type) or \
            len(args.replacement) != len(args.filename):
        print '\n\tFor every -replacement value you should pass -filename and -type'
        print '\n\t\tFilename:    %i' % len(args.filename)
        print '\n\t\tReplacement: %i' % len(args.replacement)
        print '\n\t\tType:        %i' % len(args.type)

        exit(0)

print '\n\tParsing firmware...'
a = HuaweiFirmware(open(args.firmware, 'rb').read())

if args.list:
    print '\nFiles in dat firmware:'
    files = FindFilesWithGivenName(a.file_table, '', verbose=True)
    exit()

if args.extract:
    files = FindFilesWithGivenName(a.file_table, args.extract[0])
    if len(files) == 0:
        print 'There are no files in this firmware with such name. Exitting'
        exit(-1)
    elif len(files) > 1:
        print 'Found multiple files with the same name. Choose one of them to replace:'
        j = 1
        for i in files:
            print j
            print '\t%i) Name: %s | Size: 0x%x | Crc16: 0x%x' % (j, i.filename, i.size, i.crc16)
            print '\t\t%s' % PrettyPrintPath(GetPathForObject(a.file_table, i))
            j += 1

        try:
            index = int(raw_input('# : '))
        except ValueError:
            print "That's not a number!"
            exit(-1)

        try:
            to_be_extracted = files[index-1]
        except IndexError:
            print 'Number out of range, motherfucker!'
            exit(-1)
    else:
        to_be_extracted = files[0]

    try:
        d = to_be_extracted.object.object.data
    except:
        d = to_be_extracted.object.data 
    open(args.extract[0], 'wb').write(d)

    print '\n\tExtracted to "%s"' % args.extract[0]
    exit()

for repl in range(len(args.replacement)):
    # let's try to find file with given name
    print '\n\tProcessing (%s <- %s)' % (args.filename[repl],
                                            args.replacement[repl])
                                                
    files = FindFilesWithGivenName(a.file_table, args.filename[repl])

    # get rid of "branch" objects, cus we need only "leafs"
    i = 0
    while i < len(files):
        if ".File'" in str(type(files[i])) and 'BinaryBlob' not in str(type(files[i].object)):
            del files[i]
            continue
        i += 1

    if len(files) == 0:
        print 'There are no files in this firmware with such name. Exitting'
        exit(-1)
    elif len(files) > 1:
        print 'Found multiple files with the same name. Choose one of them to replace:'
        j = 1
        for i in files:
            print j
            print '\t%i) Name: %s | Size: 0x%x | Crc16: 0x%x' % (j, i.filename, i.size, i.crc16)
            print '\t\t%s' % PrettyPrintPath(GetPathForObject(a.file_table, i))
            j += 1

        try:
            index = int(raw_input('# : '))
        except ValueError:
            print "That's not a number!"
            exit(-1)

        try:
            to_be_mod = files[index-1]
        except IndexError:
            print 'Wrong number!'
            exit(-1)
    else:
        to_be_mod = files[0]

    sNewFile = open(args.replacement[repl], 'rb').read()
    if args.type[repl] == 'bin':
        try:
            to_be_mod.object.object.data = sNewFile
        except AttributeError:
            to_be_mod.object.data = sNewFile

    # VRP CAN'T HANDLE THEM, DO NOT USE THIS OPTION
    elif args.type[repl] == 'tar.gz':
        to_be_mod.object.object.data = open(args.replacement[repl], 'rb').read()

    elif args.type[repl] == 'lzma':
        print '\n\t\tCompressing file...'
        t = gen_id()
        check_output(['lzma.exe', 'e', args.replacement[repl], \
                        t, '-lc4', '-lp2', '-pb2', '-d23'])
        sCompressed = open(t, 'rb').read()
        to_be_mod.object.data = sCompressed
        os.remove(t)

print '\n\tGenerating new firmware'
open(args.firmware + '_mod.bin', 'wb').write(a.Gen())
print '\n\tDone!'