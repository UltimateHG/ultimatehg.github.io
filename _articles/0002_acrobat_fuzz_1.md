---
id: 2
title: "Learning To Harness: Crash Coursing C"
subtitle: "Part 1: Understanding structs and pointers in a harness"
date: "2020.10.26"
tags: "c, fuzzing, adobe, acrobat dc"
---

## Foreword
Recently I was tasked with harnessing a library used by a pdf parser, so I just thought I'd like to record down the things I learn along the way as I try to crash course C in order to write harnesses to fuzz Adobe Acrobat DC. This was a pretty new experience to me as I have only mainly done software development in Java and Python alongside some web development and have never really looked too deep into C/C++/Obj-C (I learned a bit of C++ on my own but it was just merely a the most basics of the basics like the syntax and hello_world.cpp), and all the experience I've had with memory, pointers, heaps and stacks were from CTF pwn challenges. I could read some C code but never really tried creating a full executable by myself.

# Introduction
The thing that motivated me to finally pick up C was slightly linked to my last post on reproducing a patched vulnerability on pdfium. Soon after we completed that task, we were assigned again to another task, and this time it was pretty vague but quite a humongous task: To read and understand the code base of PDFium/Foxit Reader. After struggling for a while, our supervisor revealed to us that the reason we had to understand the code base was so we could learn how to harness and fuzz individual libraries in order to find exploitable bugs. This got me thinking, since we started with PDFs, why not read up more on it? And as I sifted through the articles I managed to find a rather intruiging article, titled "[50 CVEs in 50 Days: Fuzzing Adobe Reader](https://research.checkpoint.com/2018/50-adobe-cves-in-50-days/)". In the article, the authors explained the concept of fuzzers and their journey of harnessing then fuzzing the JP2KLib.dll library of Adobe Acrobat DC. The code base for Adobe Acrobat is slightly different from PDFium or Foxit Reader, but the functionalities and execution logic should be similar enough for me to be able to grasp along the way, hence I decided to take it upon myself to understand how to code a harness for a .dll library. In this post, I will be referencing a lot to the article mentioned above.

# Understanding The Basics
C, as according to its description (on wikipedia), "is a general-purpose, procedural computer programming language" and provides constructs that map efficiently to typical machine instructions. This also means that we will be dealing quite a bit with pointers as well as stack/heap space. To a pure object-oriented programmer like me with only experience in garbge-collected languages like Java, some things were quite fresh. I had to of course first learn some basics, like (heavily simplified for reading pleasure):
```c
int *number; //this defines the variable "number" as a pointer to an integer, int* number also works
int number2 = 5;
*number = number2; //using the dereference notation accesses the value at the pointer's location, thus this sets the value at number to 5
number = &number2; //this does the same thing as above, but this time referencing number2's pointer

char* str = "abcdefg";
/**
 * By assigning pointer *str to "abcdefg", *str or str[0] is 'a', str[1] is 'b' and so on.
 * If we printf as a string (printf("The string is %s\n", *str)), it will print the whole string
 */
```

This is a rough example of the different types of basic pointer referencing and logic that I had to learn and get used to first before I started on understanding how to write a harness for a .dll in order to run a fuzzer. There are many tutorials and writeups out there explaining in detail all the concepts of pointer referencing and dereferencing as well as how to properly define and intialize variables in C to prevent memory leaks, but I won't be talking too much about that here.

# Fuzzers and Harnesses
In Security Research, fuzzing is a lot more important than we might think. Fuzzing is basically taking an application and looking at the possible inputs, then thinking: how can I make the inputs weird enough that the application has an error? It's a pretty effective way to discover different edge cases as well as special cases that software developers might have missed out on or not considered when creating their program. What a fuzzer aims to do is essentially take a set of given inputs and execute the application with said inputs in succession (it's like a launch-execute-close bot). There are some famous optimized fuzzers out there like the american fuzzy loop (AFL), which only requires a minimum effective corpus, mutating said corpus to produce more possible inputs to aim for higher code coverage (higher sections of code base executed, more functions fired) and hopefully discover an edge case that causes a crash. These crashes can then be triaged and analysed on whether they could be exploited or not and if so what would be an example of a proof-of-concept exploit that could potentially exploit the application.

As fuzzers repeatedly execute an application, each separate execution would take a considerable amount of time if the application is complex (e.g. Adobe Acrobat). However, if we just targeted one specific library, load only that library and call said library similarly to how the application would call it in a normal execution cycle, the runtime would be a lot faster than if we loaded up the entire application just to fuzz the functionalities of a specific library. This is where the concept of harnesses come into play.

A harness could be thought of as a minimally working application that loads a library, accepts a given input, calls its entry functions and exits when the execution finishes. We want a harness that can accurately call as many functions as possible within the library with a given input and use the library like how the original application would, such that we create a minimally working application that only calls that library with inputs accepted by said library. An example harness can be seen [here](https://github.com/googleprojectzero/winafl/blob/master/gdiplus.cpp) (minimal harness for gdiplus, from WinAFL's github repo).
```cpp
#include <stdio.h>
#include <windows.h>
#include <gdiplus.h>

using namespace Gdiplus;

wchar_t* charToWChar(const char* text)
{
  size_t size = strlen(text) + 1;
  wchar_t* wa = new wchar_t[size];
  mbstowcs(wa,text,size);
  return wa;
}

int main(int argc, char** argv)
{
  if(argc < 2) {
    printf("Usage: %s <image file>\n", argv[0]);
    return 0;
  }

  GdiplusStartupInput gdiplusStartupInput;
  ULONG_PTR gdiplusToken;
  GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

  Image *image = NULL;
  image = new Image(charToWChar(argv[1]));
  if(image) delete image;
  
  GdiplusShutdown(gdiplusToken);

  return 0;
}
```

But as we can see here, it is able to include `gdiplus.h`, the header defining all the functions used in the `gdiplus` library. This was something that I could not do when trying to learn how to harness JP2KLib.dll, as there was no header file provided (obviously, since Adobe Acrobat DC is a closed-source application). Hence, we had to do it some other way.

# Loading the Entry Functions
Let's take a look at the post:
> JP2KLibInitEx is the first function called after loading JP2KLib. We noticed that JP2KLibInitEx takes only one argument.
> 
>We can see that it’s a struct of size 0x20 and it contains pointers to functions in AcroRd32.dll. When we encounter an unknown function, we don’t rush into reversing it as we don’t know if it’s going to be used by the target code. Instead, we point each address to a unique empty function we call “nopX” (where X is a number).
>
> We now have enough information to start writing our harness skeleton:
>
> 1. Get input file from command line arguments.
> 2. Load JP2KLib.dll.
> 3. Get a pointer to JP2KLibInitEx and call it with a struct of 8 nop functions.

Okay, let's slow down a little. Firstly, let's understand what a `struct` of size `0x20` means. `0x20` is actually hex for 32, so a `struct` of size `0x20` is 32 bytes in size. A `struct` in C allows us to declare a composite datatype. From the article's analysis, the JP2KLibInitEx function seems to take in a argument which contains 8 pointers to other functions. Since Adobe Acrobat is a 32-bit application on Windows, this means that the pointers are 4 bytes each, so 8 pointers would be 4 x 8 = 32 bytes. Hence, we define our struct, `vtable_t`, to contain 8 `int`s. Since an `int` is 4 bytes which is perfect for storing a 32-bit pointer, this also fits the input argument of JP2KLibInitEx. Hence, we can define as such:
```c
typedef struct {
  int (*funcs[8])();
} vtable_t;
```

This defines a struct containing 8 function pointers. This is because we want to initialize each individual function as a `nop` function that just prints itself and its address when called. The article made use of a macro to create the `nop` functions (`nop0` through `nop7`), and I had to alter it a little bit to get it working for me:
```c
#define NOP(x) \
  int nop##x() { \
    printf("==> nop%d called, %p\n", x, __builtin_return_address(0)); \
    return (DWORD)x; \
  }
```

I then call it before int main() in order to create the 8 `nop` functions. Then, just like in the article, I placed them in a `vtable_t` struct, loaded `JP2KLib.dll`, loaded the function `JP2KLibInitEx()` and passed the struct as an argument to the function:
```c
HMODULE jp2klib = LoadLibraryA("JP2KLib.dll");
if(jp2klib == NULL) {
  printf("failed to load directory, gle = %d\n", GetLastError());
  exit(1);
  }

LOAD_FUNC(jp2klib, JP2KLibInitEx);
//get return value by passing 0x20 vtable struct with nop functions and print return value
int ret = JP2KLibInitEx_func(&vtable);
printf("JP2KLibInitEx: ret = %d\n", ret);
```

Similarly to in the article, I used another macro to load in the function, altering it slightly to make it work for me:
```c
#define LOAD_FUNC(h, n) \
  n##_func_t n##_func = (n##_func_t)GetProcAddress(h, #n); \
  if (!n##_func) { \
    printf("failed to load function: " #n "\n"); \
    exit(1); \
  } \
  printf("pointer address of " #n ": %p\n", *n##_func);
```

One big roadblock I had was that I did not understand how the functions were loaded in. As it turned out, all I had to do was to define datatypes that "emulated" the functions I wanted to load in. This is an example of what I did for `JP2KLibInitEx()`:
```c
typedef int (__stdcall *JP2KLibInitEx_func_t)(vtable_t* vtbl);
```

It is a function that returns an `int`, and accepts a `struct` of size `0x20` as an input.

I compiled my harness with MinGW, and ran it with a dummy jpg input, and voila:
```
F:\jp2klib>fuzz.exe "198_027.jpg"
pointer address of JP2KLibInitEx: 5E713130
JP2KLibInitEx: ret = 0
```

I had successfully harnessed the `JP2KLibInitEx()` function. I then followed along what the article mentioned about the few following functions, and ended up successfully harnessing `JP2KGetMemObjEx()` and `JP2KDecOptCreate()` as well:
```c
LOAD_FUNC(jp2klib, JP2KGetMemObjEx);
//get return value and print return value
void* mem_obj = JP2KGetMemObjEx_func();
printf("JP2KGetMemObjEx: ret = %p\n", mem_obj);

LOAD_FUNC(jp2klib, JP2KDecOptCreate);
int dec_opt = JP2KDecOptCreate_func();
printf("JP2KDecOptCreate: ret = %d\n", dec_opt);
```

Similarly, I compiled the harness and executed it with an image input:
```
F:\jp2klib>fuzz.exe "198_027.jpg"
pointer address of JP2KLibInitEx: 5E713130
JP2KLibInitEx: ret = 0

pointer address of JP2KGetMemObjEx: 5E7130f0
JP2KGetMemObjEx: ret = 006LFED4

pointer address of JP2KDecOptCreate: 5E716690
==> nop4 called, 5E715DA4
==> nop7 called, 5E715DE5
JP2KDecOptCreate: ret = 4
```

As we can see, the functions have been successfully loaded. There was still one thing I could not figure out, and that was the return type of `JP2KDecOptCreate()`. As it seemed, the article used a self-defined datatype `image_t` which I assumed was a bitstream containing pixel data (I could be wrong), which I hadn't yet figured out how to define. As I mentioned, I am basically completely new to C so it actually took be embarassingly long to get hold of something so simple. And this will actually be it for this post. I will update more as I finish up the harness and start running the fuzzer.

# Final Words
Thank you for sitting through this and bearing with me (and my amateur writeup). I am new to C, so please forgive me if I made any conceptual errors. Just learning something seemingly this simple still broadened my knowledge on this subject, and security research never ceases to amaze me. I will continue to research into PDF fuzzing and update as it goes along.

Thanks for reading.