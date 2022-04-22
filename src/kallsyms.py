import r2pipe
import tqdm
import vmlinux_to_elf.kallsyms_finder as kf

def run():
    r2 = r2pipe.open()

    fname = r2.cmdj("ij")["core"]["file"]

    with open(fname, 'rb') as fd:
        kallsyms = kf.KallsymsFinder(kf.obtain_raw_kernel_from_file(fd.read()), None)
        print('[*] %d symbols found.' % len(kallsyms.symbols))

    symslen = len(kallsyms.symbols)

    for sym in tqdm.tqdm(kallsyms.symbols, desc='[*] adding symbols', ncols=80):
        r2.cmd("f kern.%s @%d" % (sym.name, sym.virtual_address))

    print('[*] Done.')

if __name__ == '__main__':
    run()