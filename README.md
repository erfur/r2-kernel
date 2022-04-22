# Kernel exploitation scripts for Radare2

Couple of scripts I wrote while I was learning kernel pwn.

## kallsysms.py

Adds kernel symbols as flags. Requires `tqdm` for verbosity.

![](img/kallsyms.gif)

The flags will be added with `kern.` prefix.

## rop.py

Search, select (with tab) and flag rop gadgets of your choice, powered by ropper and fzf.

![](img/rop.gif)

If the script is running for the first time, it will generate a `gadgets.txt` file. This
will take some time. After that the flags will be added with `gadget.` prefix.
