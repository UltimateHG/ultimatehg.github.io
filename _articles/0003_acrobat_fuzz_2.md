---
id: 3
title: "Learning To Harness: Custom Stream Decoders"
subtitle: "Part 2: Reverse Engineering a Stream Decoder"
date: "2020.11.20"
tags: "c, fuzzing, adobe, acrobat dc"
---

## Foreword
I've been gone for a little long this time, mainly because I took the time to finish the entire book of "The C Programming Language" by Brian Kernighan and Dennis Ritchie. It was a rather quick read (I guess C is not a very complex language after all) compared to other languages I've learnt (objected-oriented languages, especially), but it helped me immensely. Adobe Acrobat and Adobe Reader has changed a lot since the article I was following in the last article had been written, that JP2KLib also had a bit of a minor change, so I ended up having to change some things and do a bit of debugging by myself to fix the harness, and I will be covering all of that here.

# Introduction
The last time I touched this, I was simply following suit along with the article "[50 CVEs in 50 Days](https://research.checkpoint.com/2018/50-adobe-cves-in-50-days/)" written by Yoav Alon and Netanel Ben-Simon. I stopped the previous time at `JP2KDecOptCreate`, where my function returned 4, which was not the correct return value for this function. This time, with much better knowledge and more experience in debugging as well as reverse engineering the JP2K library, I decided that there were many things that I had to make sure by myself to ensure that the harness would not break. I will be using windbg and IDA a lot through this post so please bear with me. Once again, let's take this slowly.

# Implementing the NOP Functions
I first needed to figure out what nop4 and nop7 could possibly be, as they were both called by `JP2KDecOptCreate`. The article mentioned that they were wrappers around `malloc` and `memset`, but I had to make sure for myself. I fired up windbg and set a breakpoint at nop4 and nop7 respectively, then stepped forward one at a time until eventually I arrived at the following:<br>
nop4:
```
eax=0ebc3db6 ebx=00000000 ecx=75e1edb0 edx=01400200 esi=75e1edb0 edi=222d65c8
eip=79c576d7 esp=00b8cf70 ebp=00b8cf78 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
Acrobat!AcroWinMainSandbox+0x33b7:
79c576d7 ffd6            call    esi {ucrtbase!malloc (75e1edb0)}
```

nop7:
```
eax=00000000 ebx=240ee4f0 ecx=240ee4f0 edx=11010100 esi=7a3f37c0 edi=00000058
eip=79c4d3e0 esp=00b8cf44 ebp=00b8cf70 iopl=0         nv up ei pl nz na pe nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000206
Acrobat+0x4d3e0:
79c4d3e0 ff25f0413a7b    jmp     dword ptr [Acrobat!CTJPEGThrowException+0x2851f0 (7b3a41f0)] ds:002b:7b3a41f0={VCRUNTIME140!memset (72183c30)}
```

There we go, so now we know for sure that at least these 2 wrappers have not changed. I went ahead and implemented them. The malloc wrapper was pretty straightforward to implement, it just takes in an argument for size to pass to `malloc` and returns the address that `malloc` returns. The `memset` was also pretty straightforward, as even though it took in 3 args it took them in the perfect order that `memset` also accepted: `void* dest, int val, int size` in this exact order. After implementing them, I ran the harness again to make sure it was not crashing, and it worked.
```
...
pointer address of JP2KDecOptCreate: 79A16690
==> nop4 (malloc wrapper) called, with args size:58
==> nop7 (memset wrapper) called with args val:0, size:58, dest:001A1C48
JP2KDecOptCreate: ret = 001A1C48
```

The article also mentioned that nop5 and nop6 were wrappers around `free` and `memcpy` respectively, but I also had to make sure for myself:<br>
nop5:
```
eax=7bc6c51c ebx=00000000 ecx=79c735d0 edx=04000000 esi=79c735d0 edi=00000000
eip=79c5820c esp=00b8cd50 ebp=00b8cd58 iopl=0         nv up ei pl nz na po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000202
Acrobat!AcroWinMainSandbox+0x3eec:
79c5820c 8b7018          mov     esi,dword ptr [eax+18h] ds:002b:7bc6c534={ucrtbase!free (75e228c0)}
```

nop6:
```
eax=0f47e6f0 ebx=0000005c ecx=7a3f3780 edx=11010100 esi=7a3f3780 edi=2410e510
eip=79a1600f esp=00b8cd20 ebp=00b8cd30 iopl=0         nv up ei pl zr na pe cy
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000247
JP2KLib!JP2KTileGeometryRegionIsTile+0x3bf:
79a1600f ffd6            call    esi {Acrobat!AX_PDXlateToHostEx+0x418530 (7a3f3780)}
```

As you can see, nop5 was straightforward but nop6 wasn't quite so, so I fired up IDA and looked into the function it was calling and sure enough, it was a memcpy wrapper:<br><br>
![](https://i.ibb.co/5xDQS5T/nop6.png)

I implemented nop4, nop5, nop6 and nop7 and then moved onwards to the next functions.

# Implementing a Custom File Stream Class
Following the article, I added `JP2KDecOptInitToDefaults` and passed it the return value from `JP2KDecOptCreate`. This was definitely still the case as a quick run in windbg shows that:
```
eax=240ee4f0 ebx=00000000 ecx=00000001 edx=00000058 esi=79fffb30 edi=240d3e88
eip=79a1669b esp=00b8cf80 ebp=00b8d03c iopl=0         nv up ei pl nz ac po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000212
JP2KLib!JP2KDecOptCreate+0xb:
79a1669b c3              ret
```
and
```
eax=79a166c0 ebx=00000000 ecx=00000001 edx=00000058 esi=240ee4f0 edi=240d3e88
eip=79a166c0 esp=00b8cf7c ebp=00b8d03c iopl=0         nv up ei pl nz ac po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000212
JP2KLib!JP2KDecOptInitToDefaults:
79a166c0 55              push    ebp
0:000> dd esp
00b8cf7c  7a3f3d5e 240ee4f0 42bb8065 222d65c8
00b8cf8c  2410a4c4 00000000 00000000 00000000
00b8cf9c  00b8cfcc 00000003 42bb9fe5 0000040c
00b8cfac  00b8d024 240d4114 00000008 00002054
00b8cfbc  7759a180 1e71d298 154a0000 1e71d298
00b8cfcc  00b8d0cc 79e71800 154ff8a4 00000000
00b8cfdc  775af94e 00000008 00000000 00002054
00b8cfec  00002054 00000000 00b8d00c 75e20647
```

From here, we move on to `JP2KImageInitDecoderEx`, which still takes in 5 arguments, and with windbg we can easily see that it took in 2 return values that we got earlier:
```
eax=79a150b0 ebx=240eda10 ecx=240a3948 edx=00000000 esi=7a3d8da0 edi=2410a4c4
eip=79a150b0 esp=00b8cf54 ebp=00b8d040 iopl=0         nv up ei pl nz ac po nc
cs=0023  ss=002b  ds=002b  es=002b  fs=0053  gs=002b             efl=00000212
JP2KLib!JP2KImageInitDecoderEx:
79a150b0 6a24            push    24h
0:000> dd esp
00b8cf54  7a3f56a9 240ea4b8 240a3948 240d3e88
00b8cf64  240ee4f0 223d14f0 240eda10 7a3dc3a0
00b8cf74  2410a4c4 240eda10 00000000 00000054
00b8cf84  42bb8065 222d65c8 2410a4c4 00000000
00b8cf94  00000000 00000000 00b8cfcc 00000003
00b8cfa4  42bb9fe5 0000040c 00b8d024 240d4114
00b8cfb4  00000008 00002054 7759a180 1e71d298
00b8cfc4  154a0000 1e71d298 00b8d0cc 79e71800
```

To save time and space, `240ea4b8` was the return value from `JP2KImageCreate`, followed by 2 unknown structs, `240ee4f0` was the return value from `JP2KDecOptCreate` (which you can see from above actually), followed by a last unknown struct. That's right, this function had changed since the article I was referring to was written, so it no longer took in the return value of `JP2KGetMemObjEx` as its last argument, even though `JP2KGetMemObjEx` was still called in the correct order (and a lot of times too!). Weird, but we could still move on. For now, I used a placeholder for the last argument and followed what the article did to also arrive at the same conclusion: the second argument was a pointer to a file stream object and the third argument was a struct of functions that would be carried out on the second argument. Hence, I also had to create my own file object and file stream functions to pass into this function:
```c
typedef struct {
  FILE *fileptr;
} file_obj_t;
```

It was just a simple struct that took in 1 `FILE*` as its only variable. To save space and clutter, I will not be showing every single function that I created, but the filestream functions were something like these:<br>
is_readable:
```c
int file_obj_is_readable(const file_obj_t *file) {
  printf("file_obj_is_readable called\n");
  return (feof(file->fileptr)) ? 0:1;
}
```

write:
```c
int file_obj_write(void* fileptr, unsigned char *data, int param2) {
  printf("file_obj_write called with params fileptr=%p, data=%p, param2=%d\n", fileptr, data, param2);
  return fwrite(data, 1, param2, fileptr);
}
```

The article mentioned at one point that they realized that the `SEEK` constants were different in Adobe compared to in libc, so I had to swap them too (`SEEK_SET` and `SEEK_CUR` were swapped, same as mentioned in the article), leading me to do some sort of a mini-workaround in my seek function:
```c
int file_obj_seek(void* fileptr, int offset, uint64_t whence) {
  printf("file_obj_seek called with fileptr=%p, offset=%d, whence=%d\n", fileptr, offset, whence);
  uint64_t actual;
  switch (whence) {
    case 0:
      actual = SEEK_CUR;
      break;
    case 1:
      actual = SEEK_SET;
      break;
    case 2:
      actual = SEEK_END;
      break;
  }
  return fseek(fileptr, offset, actual);
}
```

Not the prettiest workaround, but it works. After this, I simply initialized a file_obj_t and created a struct that contained all my custom file stream functions and passed it into `JP2KImageInitDecoderEx` with the last argument still being an unknown placeholder struct. Similarly to the article, my `JP2KImageInitDecoderEx` would also return 0 only if it succeeded, so I added in a check to make sure I wasn't continuing execution with a failed image decode. I ended up with something like this:
```c
//create vtable
vtable_t procs;
//assign relevant func pointers
procs.funcs[0] = (void*)nop_ret_0;
procs.funcs[1] = (void*)file_obj_die;
procs.funcs[2] = (void*)file_obj_read;
procs.funcs[3] = (void*)file_obj_write;
procs.funcs[4] = (void*)file_obj_seek;
procs.funcs[5] = (void*)file_obj_tellpos;
procs.funcs[6] = (void*)file_obj_is_seekable;
procs.funcs[7] = (void*)file_obj_is_readable;
procs.funcs[8] = (void*)file_obj_is_writeable;
procs.funcs[9] = (void*)&procs;

//read file and store in file obj
file_obj_t fobj;
init_file(&fobj, argv[1]);
if(!(fobj.fileptr)) {
  printf("failed to load file object\n");
  return 1;
}
printf("f_obj is at address: %p\n   with fobj->fileptr at: %p\n", fobj, fobj.fileptr);
    
unknown* u = malloc(sizeof(unknown));
u->p1 = malloc(16);

printf("struct u has address: %p with p1=%p\n",u,u->p1);

ret = JP2KImageInitDecoderEx_func(image, &fobj, &procs, dec_opt, u);
printf("JP2KImageInitDecoderEx: ret = %d\n", ret);
//if failed to decode we want to just exit so there's no bogus crashes
if(ret != 0)
  printf("failed to decode.\n");
```

I also made sure to add in the relevant destroy functions to destroy all data if `JP2KImageInitDecoderEx` failed to decode to prevent memory leaks. After running the new harness (a lot of output has been truncated with "..." as they were printed by the wrapper functions "nop4 (malloc wrapper) called: ....." or file stream functions "file_obj_write called" and they were called a lot), we could confirm that it was working:
```
pointer address of JP2KImageInitDecoderEx: 684D50B0
file "sample1.jp2" initiated
initial fileptr is 95E11CFF
f_obj is at address: 75D74660
   with fobj->fileptr at: 75D74660
struct u has address: 058DCFF8 with p1=058DEFF0
==> nop4 (malloc wrapper) called, with args size:40 pointer: 684D5DA4
==> nop7 (memset wrapper) called with args val:0, size:40, dest:058E0FC0, pointer: 684D5DE5
file_obj_is_seekable called
file_obj_is_readable called
file_obj_is_writeable called
...
...
=> nop4 (malloc wrapper) called, with args size:c pointer: 684D5F6E
==> nop4 (malloc wrapper) called, with args size:c pointer: 684D5F6E
==> nop5 (free wrapper) called at location:0593CFF0, pointer: 684D5E80
==> nop5 (free wrapper) called at location:0593EFF0, pointer: 684D5E80
==> nop5 (free wrapper) called at location:05940FF0, pointer: 684D5E80
==> nop5 (free wrapper) called at location:058E7FC0, pointer: 684D5E80
JP2KImageInitDecoderEx: ret = 0
```

Huzzah, it returns 0! We can now move on. This took waaaaay longer than I would've hoped.
> Common error return values that I got:<br>
> 17: This meant that the input image was not a valid jp2 image, or was not a jp2 image at all.<br>
> 26: This meant that something went wrong in the process of decoding the image. Something went wrong with one or more of the file stream functions.

Anecdote: I was tearing my hair out because `JP2KImageInitDecoderEx` kept failing for me even though I felt I had already implemented everything correctly, but it turned out that for certain file stream functions, the _file stream pointer itself_ was passed directly into them instead of just the _custom file stream object_.

# Implementing the Last Functions
According to the article, they only had to implement `JP2KImageDataCreate`, `JP2KImageGetMaxRes` and `JP2KImageDecodeTileInterleaved`. After going through windbg and consulting some people, I believed that this still held true as a lot of the other functions that were called were likely unrelated to the parsing of JP2 images and thus were not needed in the harness.

`JP2KImageDataCreate` and `JP2KImageGetMaxRes` were similar to in the article, I just had to call the former and pass its return value to the latter and save both return values before moving on.

Now began the nightmare (again, after `JP2KImageInitDecoderEx`). This function took in a massive amount of 7 arguments (hadn't changed since the article was written) and through windbg I could double confirm that it took in the return values of `JP2KImageCreate`, `JP2KImageGetMaxRes` and `JP2KImageDataCreate`. The 2nd and 6th parameters were also found to be `null` and the 4th and 5th arguments often were `8` and `0xff` respectively so I took the article's word that it did depend on the colour depth so I also decided to leave it as `8` and `0xff`, which left me with:
```c
int max_res = JP2KImageGetMaxRes_func(image);
printf("JP2KImageGetMaxRes: ret = %d\n", max_res);

void* image_data = JP2KImageDataCreate_func();
printf("JP2KImageDataCreate: ret = %p\n", image_data);

ret = JP2KImageDecodeTileInterleaved_func(image, 0, max_res, 8, 0xff, 0, image_data);
printf("JP2KImageDecodeTileInterleaved called with params max_res=%d: ret = %d\n", max_res, ret);
```

After running it once, it ran successfully, so I also called `JP2KImageDataDestroy`, `JP2KImageDestroy`, and `JP2KDecOptDestroy` at the end to prevent memory leaks. However...

## The Work was Not Done
Because the library had changed over the years, when I tried running my harness in winafl, I had a suspiciously low stability (<80%) and also suspiciously low amount of paths (it never reached >300!!). This meant that I was likely not hitting all the correct parsing functions, so I had to go through slowly to find out what was wrong. I realized 2 main things:

1. When running through windbg, `JP2KImageDecodeTileInterleaved` ALWAYS returned 0, but mine would always return 8.
2. nop0 was called at the end of `JP2KImageDecodeTileInterleaved`, and even though the article mentioned nothing about implementing that, after setting a breakpoint in windbg it turned out that nop0 was likely an important parsing function as it eventually lead to multiple calls of `CopyRect` and it seemed to call many important subroutines in IDA as well.


# Final Words
What did this mean? This meant that I had to figure out what nop0 was exactly and implement it, as well as make sure that all my other functions were correctly harnessed.  I had learnt a lot and gotten a lot more familiar with the rev-debugging process and this was definitely fun, albeit stressful and frustrating. I'm still in the process of reverse engineering the missing link of my harness, so hopefully another writeup would come soon after I figure things out. But I guess that's it for now.

Thanks for reading.