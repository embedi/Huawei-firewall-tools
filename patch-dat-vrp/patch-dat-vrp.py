import argparse, re, struct
from subprocess import check_output
from capstone import *
from elftools.elf.elffile import ELFFile

# two of these functions can be replaced :)

lFuncsCanBeReplaced = {
    'cvmx_error_initialize_cn68xx' : None,
    'cvmx_error_initialize_cn66xx' : None,
    'cvmx_error_initialize_cn61xx' : None
}

COMPILER_PATH = '/home/userr/work/OCTEON-SDK/tools-gcc-4.3/bin/mips64-octeon-linux-gnu-gcc'

parser = argparse.ArgumentParser(description='VRP patcher')
parser.add_argument('vrp', help='Path to vrp to mess with')
parser.add_argument('injection', help='Path to .c (or object .o) file with code to be injected')
parser.add_argument('-splice_addr', help='Hex string representing virtual address of splice')
parser.add_argument('-donor', help='Name of VRP function to be replace.')
args = parser.parse_args()

if args.injection[-2:] == '.c':
    print '\nCompiling source file...'
    # mips64-linux-gnuabi64-gcc
    result = check_output([COMPILER_PATH,\
                                '-fpic', '-c', args.injection])
    print '\nSuccessfully compiled code!'
    args.injection = args.injection[:-2] + '.o'

print '\nGetting info about functions we can overwrite...'

if args.donor:
    lFuncsCanBeReplaced[args.donor] = None

vrp = ELFFile(open(args.vrp, 'rb'))
for section in vrp.iter_sections():
    if 'SymbolTableSectio' in str(type(section)):
        for sFuncName in lFuncsCanBeReplaced.keys():
            lFuncsCanBeReplaced[sFuncName] = section.get_symbol_by_name(sFuncName)[0].entry.st_value
            if lFuncsCanBeReplaced[sFuncName] is None:
                print '\nCouldn\'t find symbol for %s, deleting list entry' % sFuncName
                lFuncsCanBeReplaced.pop(sFuncName, None)
                if args.donor == sFuncName:
                    print 'Exitting'
                    exit()

print '\nParsing object file of code to be injected'
iInjectEOP = None
injection = ELFFile(open(args.injection, 'rb'))
# find unresolved symbols
lToResolve = {}
lWontResolve = ['__gnu_local_gp']
for section in injection.iter_sections():
    if 'SymbolTableSection' in str(type(section)):
        for i in xrange(section.num_symbols()):
            t = section.get_symbol(i)
            # print '0x%x | 0x%x | %s | 0x%x' % (i, t.entry.st_size, t.name, t.entry.st_value)
            if '.' not in t.name and \
                len(t.name) >= 1 and \
                not any(x in t.name for x in lWontResolve):
                lToResolve[i] = { 
                    'name' : t.name,
                    'isInternal': False if t.entry.st_size == 0 else True
                    }
            if t.name == 'main':
                iInjectEOP = t.entry.st_value


# TO DO choose function somehow better
if args.donor:
    iBaseOfInjectInVrp = lFuncsCanBeReplaced[args.donor]
else:
    iBaseOfInjectInVrp = lFuncsCanBeReplaced['cvmx_error_initialize_cn68xx']

# parse relocs and pull
sRelocs = injection.get_section_by_name('.rela.text').data()
for i in xrange(0, len(sRelocs), 0x18):
    offset = struct.unpack('>Q', sRelocs[i:i+8])[0]
    symbolIndex = struct.unpack('>I', sRelocs[i+8:i+12])[0]
    relType = struct.unpack('>I', sRelocs[i+12:i+16])[0]

    if symbolIndex in lToResolve and relType == 0xB:
        try:
            if lToResolve[symbolIndex]['offset']:
                pass
        except KeyError:
            lToResolve[symbolIndex]['offset'] = []

        lToResolve[symbolIndex]['offset'].append(offset)
        # print '%s | 0x%x | 0x%x' % (lToResolve[symbolIndex]['name'], symbolIndex, lToResolve[symbolIndex]['offset'])
        if lToResolve[symbolIndex]['isInternal'] == False:
            _object = vrp
            msg = 'vrp'
        else:
            _object = injection
            msg = 'injection'
        for section in _object.iter_sections():
            if 'SymbolTableSectio' in str(type(section)):
                toResolve = section.get_symbol_by_name(lToResolve[symbolIndex]['name'])
                if toResolve is None:
                    print 'Failed to resolve \'%s\' function used in %s' % \
                        (lToResolve[symbolIndex]['name'], msg)
                    exit()
                else:
                    lToResolve[symbolIndex]['resolvedAddr'] = toResolve[0].entry.st_value
                    if msg == 'injection':
                        lToResolve[symbolIndex]['resolvedAddr'] += iBaseOfInjectInVrp

for k in lToResolve.keys():
    if 'offset' not in lToResolve[k]:
        del lToResolve[k] 


print '\nList of functions to resolve with reloc info:'
for i in lToResolve:
    print '\t%s of index 0x%x should be resolved at %s with 0x%x' % \
        (lToResolve[i]['name'], i, str(lToResolve[i]['offset']), lToResolve[i]['resolvedAddr'])

# ------ No optimizations! ------
#     ld      $t9, (do_meh & 0xFFFF)($gp)
#     jalr    $t9
#     nop
# ------ Goes to  ------
#     nop
#     jal the_real_proc_addr
#     nop


sResolvedCode = injection.get_section_by_name('.text').data()
for i in lToResolve:
    for offset in lToResolve[i]['offset']:
        sResolvedCode = sResolvedCode[:offset] + \
                '\x00' * 4 + \
                struct.pack('>I', (3 << 26) | lToResolve[i]['resolvedAddr'] >> 2) + '\x00' * 4 + \
                sResolvedCode[offset+12:]

# rewrite code in VRP binary

sVrp = open(args.vrp, 'rb').read()
oVrpText = vrp.get_section_by_name('.text')
iVrpTextOffs = oVrpText['sh_offset']
iVrpTextSize = oVrpText['sh_size']
iVrpTextAddr = oVrpText['sh_addr']
# print 'sh_offset == 0x%x' % iVrpTextOffs
# print 'sh_size == 0x%x' % iVrpTextSize
# print 'sh_addr == 0x%x' % iVrpTextAddr

# replace .text with patched one
oVrpText = sVrp[iVrpTextOffs:iVrpTextOffs+iVrpTextSize]
oVrpText = oVrpText[:iBaseOfInjectInVrp-iVrpTextAddr] + \
            sResolvedCode + \
             oVrpText[iBaseOfInjectInVrp-iVrpTextAddr+len(sResolvedCode):]

if args.splice_addr:
    # inject splice
    print '\niInjectEOP at 0x%x' % iInjectEOP
    iSpliceAddr = int(args.splice_addr, 16)
    # jae INJECTION_ADDR
    # nop
    # jr $ra
    # nop
    sSplice = struct.pack('>I', (3 << 26) |  (iBaseOfInjectInVrp + iInjectEOP) >> 2) + \
                '\x00' * 4 + '\x03\xE0\x00\x08' + '\x00' * 4 

    oVrpText = oVrpText[:iSpliceAddr-iVrpTextAddr] + \
                sSplice + \
                    oVrpText[iSpliceAddr-iVrpTextAddr+len(sSplice):]            

# combine ELF back
sVrp = sVrp[:iVrpTextOffs] + \
         oVrpText + \
            sVrp[iVrpTextOffs+iVrpTextSize:]


open(args.vrp + '_patched', 'wb').write(sVrp)
print '\nDone!'