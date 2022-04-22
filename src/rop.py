import r2pipe
from pyfzf.pyfzf import FzfPrompt
import string
from ropper import RopperService

# not all options need to be given
options = {'color' : False,     # if gadgets are printed, use colored output: default: False
            'badbytes': '',   # bad bytes which should not be in addresses or ropchains; default: ''
            'all' : False,      # Show all gadgets, this means to not remove double gadgets; default: False
            'inst_count' : 6,   # Number of instructions in a gadget; default: 6
            'type' : 'all',     # rop, jop, sys, all; default: all
            'detailed' : False} # if gadgets are printed, use detailed output; default: False

def run():
    r2 = r2pipe.open()
    fzf = FzfPrompt()

    fname = r2.cmdj('ij')['core']['file']

    try:
        with open('gadgets.txt') as fd:
            gadgets = fd.read().split('\n')

    except FileNotFoundError:
        print('[*] gadgets.txt not found, generating now.')
        rs = RopperService(options)

        # TODO: add the option to read from r2 memory
        rs.addFile(fname)

        print('[*] loading gadgets, this might take some time...')
        rs.loadGadgetsFor()

        gadgets = [g.simpleString() for g in rs.getFileFor(fname).gadgets]
        print('[*] %d gadgets loaded.' % len(gadgets))

        with open('gadgets.txt', 'w') as fd:
            fd.write('\n'.join(gadgets))

    try:
        selection = fzf.prompt(gadgets, '+s -m -e --print-query')
        print('[*] you selected: %s' % selection)
    except:
        print('[-] no gadget available/selected.')
        return

    query = selection.pop(0).strip()
    flag_prefix = ''.join(i for i in query if i not in '\',\\$;').replace(' ', '_')
    print('[*] flag prefix: %s' % flag_prefix)

    if selection_len := len(selection):
        for cnt, gadget in enumerate(selection):
            addr, instrs = gadget.split(':')
            addr = int(addr, 16)
            instrs = instrs.strip()

            r2.cmd('f gadget.%s.%d @%d' % (flag_prefix, cnt, addr))

        print('[*] flagged %d gadgets.' % selection_len)

if __name__ == '__main__':
    run()
