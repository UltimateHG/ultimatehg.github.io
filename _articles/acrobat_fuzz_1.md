---
id: 2
title: "Learning To Harness: Crash Coursing C"
subtitle: "Part 1: Understanding structs and pointers in a harness"
date: "2020.10.26"
tags: "c, fuzzing, adobe, acrobat dc"
---

## Foreword
Ok yes, I know for those that have already learnt C, Obj-C or C++, or those who have been in the infosec field for some time, this may seem like a really dumb post (please don't palm your face too hard), but I just thought I'd like to record down the things I learn along the way as I try to crash course C in order to write harnesses to fuzz Adobe Acrobat DC. Just for a little background, I have only mainly done software development in Java and Python alongside some web development and have never really looked too deep into C/C++/Obj-C (I learned a bit of C++ on my own but it was just merely a the most basics of the basics like the syntax and hello_world.cpp). This was a pretty new experience to me as all the experience I've had with memory, pointers, heaps and stacks were from CTF binary exploitation challenges. I could read some C code but never really tried coding a full executable by myself.

# Introduction
The thing that motivated me to finally pick up C was slightly linked to my last post on reproducing a patched vulnerability on pdfium. Soon after we completed that task, we were assigned again to another task, and this time it was pretty insane. The only instruction we were given was: "Read and understand the code base of PDFium/Foxit Reader". After struggling for a while, our supervisor revealed to us that the reason we had to understand the code base was so we could learn how to harness and fuzz individual libraries in order to find exploitable bugs. This got me thinking, since we started with PDFs, why not read up more on it? And as I sifted through the articles I managed to find a rather intruiging article, titled "[50 CVEs in 50 Days: Fuzzing Adobe Reader](https://research.checkpoint.com/2018/50-adobe-cves-in-50-days/)". In the article, the authors explained the concept of fuzzers and their journey of harnessing then fuzzing the JP2KLib.dll library of Adobe Acrobat DC. The code base for Adobe Acrobat is slightly different from PDFium or Foxit Reader, but the functionalities and execution logic should be similar enough for me to be able to grasp along the way, hence I decided to take it upon myself to understand how to code a harness for a .dll library. In this post, I will be referencing a lot to the article mentioned above.

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
In Security Research, fuzzing is a lot more important than we might think. Fuzzing is basically taking an application and looking at its inputs, then thinking: how can I make this input so weird that the application has an error? It is a pretty effective way to discover many different edge cases as well as special cases that the developers of an application might have missed or not considered when programming their application. What a fuzzer aims to do is essentially take all its given inputs (the "corpus") execute the application with these inputs one after another, immediately executing again with the next input the moment the application exits (it's like a launch-execute-close bot). There are now some very famous optimized fuzzers out there like the american fuzzy loop (AFL), which only requires a minimum effective corpus, mutating said corpus to produce more possible inputs to aim for higher code coverage (higher sections of code base executed, more functions fired) and hopefully discover an edge case that causes a crash. These crashes can then be triaged and analysed on whether they could be exploited or not (e.g. is it a vulnerability?) and if so what is an example of a proof-of-concept exploit that could potentially exploit the application.

As fuzzers repeatedly execute an application, it would take extermely long per execution if the application is big, say, the whole of Adobe Acrobat. However, what if we just targeted one specific library (load only that library) and call that library similarly to how normal functions within the application would call it and see how we could exploit that particular library? The runtime would be a lot faster than if we loaded up the entire application just to fuzz the functionalities of said library. This is where the concept of harnesses come into play.

A harness could be thought of as a minimally working program that loads a library with a given input, call its entry functions and exits when the functions finish executing in the library. We want a harness that can accurately call as many functions as possible within the library with a given input and use the library like how the original application would, such that we create a minimally working application that only calls that library with inputs accepted by said library. An example harness can be seen [here](https://github.com/googleprojectzero/winafl/blob/master/gdiplus.cpp) (minimal harness for gdiplus, from WinAFL's github repo).
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

But as we can see here, it is able to include `gdiplus.h`, the header defining all the functions used in the `gdiplus` library. This was something that I could not do when trying to learn how the article harnessed JP2KLib.dll, as there was no header file provided (obviously, since Adobe Acrobat DC is a closed source application). Hence, we have to do it some other way.

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

Okay, let's slow down a little bit. Firstly, what is a `struct` of size `0x20`? `0x20` is actually hex for 32, so a `struct` of size 0x20 is 32 bytes in size. Let's break it down slowly. A `struct` in C allows us to declare a composite datatype. From the article's analysis, the JP2KLibInitEx function seems to take in a argument which contains 8 pointers to other functions. Since Adobe Acrobat is a 32-bit application on Windows, this means that the pointers are 4 bytes each, so 8 pointers would be 4 x 8 = 32 bytes. Hence, we define our struct, `vtable_t`, to contain 8 `int` functions (8 functions that return int). Since an `int` is 4 bytes, perfect for storing a 32-bit pointer, this also fits the input argument of JP2KLibInitEx. Hence, we can define as such:
```c
typedef struct {
  int (*funcs[8])();
} vtable_t;
```

This defines a struct containing 8 function pointers. This is because we want to initialize each individual function as a `nop` function that just prints itself when called together with its address and returns. The article made use of a macro to create the `nop` functions (`nop0` through `nop7`), and I had to alter it a little bit to get it working for me:
```c
#define NOP(x) \
  int nop##x() { \
    printf("==> nop%d called, %p\n", x, __builtin_return_address(0)); \
    return (DWORD)x; \
  }
```

I then call it before int main() in order to create the 8 `nop` functions. Then, just like in the article, I placed them in a `vtable_t` struct, loaded JP2KLib.dll, loaded the function JP2KLibInitEx() and passed the struct as an argument to the function:
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

I compiled my harness with MinGW (remember to compile it in 32-bit because Acrobat dlls are 32-bit!), and ran it with a dummy .jpg input, and voila:
```
F:\jp2klib>fuzz.exe "198_027.jpg"
pointer address of JP2KLibInitEx: 5E713130
JP2KLibInitEx: ret = 0
```

I have just successfully harnessed the `JP2KLibInitEx()` function! I then followed along what the article mentioned about the few following functions, and ended up successfully harnessing `JP2KGetMemObjEx()` and `JP2KDecOptCreate()` as well:
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

As we can see, the functions have been successfully loaded. There is still one thing I could not figure out, and that is the return type of `JP2KDecOptCreate()`. As it seemed, the article used a self-defined datatype `image_t` which I assume is a bitstream containing pixel data (I could be wrong), which I haven't yet figured out how to define. As I mentioned, I am basically completely new to C so it actually took be embarassingly long to get hold of something so simple. And this will actually be it for this post. I will update more as I finish up the harness and start running the fuzzer, but this is it for now.

# Final Words
I know that I am new to C, and I daresay that I am new to infosec as well, so I would gladly learn from my mistakes if I were to make any, and I would also like to thank you for sitting through this and bearing with me (and my amateur writeup). Likewise, if I made any serious conceptual errors or if there's anything you would like to correct me on or would like me to remove, feel free to email me at yitiancw02@gmail.com and I would make the necessary changes. Just learning something seemingly this simple still broadened my knowledge on this subject, and security research never fails to amaze me. I will continue to research into PDF fuzzing and hopefully gain something out of it eventually.

Thanks for reading.