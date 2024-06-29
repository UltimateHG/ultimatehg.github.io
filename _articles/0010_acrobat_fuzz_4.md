---
id: 10
title: "Learning To Harness: Update"
subtitle: "Minor Updates on Fuzzing Results"
date: "2021.01.14"
tags: "c, fuzzing, adobe, acrobat dc, winafl, vulnerability research"
---

EDIT: I realized that I forgot to publish after writing, so this post was published a _little bit_ later than the intended date, whoops.

## Foreword
The last time round, I managed to finish the `JP2KLib.dll` harness with the help of a colleague and began fuzzing with a corpus that I formed by both web scraping and downloading from different public corpuses like the ones from The Chromium Project. This will be a relatively short post that just covers some updates on fuzzing results, and one particularly interesting crash that I managed to get (but ultimately did not result in anything worthwhile, unfortunately).

# Triaging Crashes
There were a lot of bogus crashes, some of which would crash the harness but not Acrobat and some of which doesn't even crash the harness but somehow crashed in WinAFL, likely due to either running out of memory or due to dynamorio's instrumentation messing with the execution of the harness. Through running every legitimate crash in Acrobat, we found out that interestingly and expectedly enough, Acrobat has implemented a lot of extra error handling that we did not implement.

There was one particular crash that stood out, however, and even if it didn't amount to anything in the end it still was a very interesting crash. One of the first things I noticed was that it was the only crash I got which WinAFL named as a heap corruption crash, whereas most if not all other crashes would usually be labelled as access violation exception crashes. This got me really interested, so I attempted to open the jp2 file in Acrobat DC. Interestingly enough, Acrobat went completely unresponsive and without fail this would happen every time. I thus created a PDF file `crash.pdf` with this image embedded within and turned pageheap on for Acrobat.exe and AcroRd32.exe and attempted to run the pdf file, and to my surprise and my (then) extreme joy, Acrobat crashed a few seconds after attempting to load the pdf file. Looking at my event viewer, I could also see that Application Verifier had crashed with the following details:
```
Faulting application name: Acrobat.exe, version: 20.9.20074.61578, time stamp: 0x5efa5092
Faulting module name: verifier.dll, version: 10.0.19041.1, time stamp: 0xd131439b
Exception code: 0xc0000421
Fault offset: 0x0000dead
Faulting process ID: 0x4bf0
Faulting application start time: 0x01d6f92621b49387
Faulting application path: C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\Acrobat.exe
Faulting module path: C:\Windows\SysWOW64\verifier.dll
Report ID: 0d63eb80-29d2-4d3c-95c5-1c25961208ed
Faulting package full name: 
Faulting package-relative application ID: 
```

Now, this exception code `0xc0000421` meant that application verifier had hit a verifier stop, which in turn meant that verifier had caught an error, likely a heap corruption. Hence, I opened `crash.pdf` with Acrobat in WinDBG and sure enough:
```
ModLoad: 7b6d0000 7b7a0000   C:\Program Files (x86)\Adobe\Acrobat DC\Acrobat\JP2KLib.dll
(7544.6ce4): C++ EH exception - code e06d7363 (first chance)


===========================================================
VERIFIER STOP 00000007: pid 0x7544: block already freed 

	09601000 : Heap handle
	308B2444 : Heap block
	00000004 : Block size
	00000000 : 
===========================================================
This verifier stop is not continuable. Process will be terminated 
when you use the `go' debugger command.
===========================================================
```

However, this is where the interesting bit comes in. We attempt to analyse the double free by calling `!heap -p -a` on the heap block, and this happens:
```
0:000> !heap -p -a 308B2444
 
```

Yep, nothing. This heap block was never referenced or allocated or freed. At this point I was extremely confused, was I doing the debugging wrongly? No, it couldn't be, I made sure by restarting several times, and every time I would get the same outcome -- `!heap -p -a` showing me absolutely nothing. Timeless (Time Travel) debugging didn't help either, and the even more puzzling thing was that the stacktrace for the timeless debugging dump differed from the stacktrace from a non-TTD run, which technically shouldn't be the case. Another completely puzzling thing was that at times Acrobat wouldn't even crash. When setting breakpoints and running in WinDBG at times, Acrobat actually catches an error and displays a popup window, but this NEVER happens with pageheap disabled. So our situation was then this: Acrobat goes unresponsive forever with `crash.pdf` when pageheap is disabled, and Acrobat crashes with `crash.pdf` when pageheap is enabled. WinDBG catches a double free, but the double free references a block that is ever referenced. Sometimes, Acrobat actually catches the error and does NOT crash, but this only happens with pageheap enabled.

After a ton more analysis and testing, we concluded that this was not an actual double free and was likely due to 1) TTD messing with the execution flow of the program and 2) pageheap causing the program to run out of space/memory. This was thus not an exploitable bug, and likely not a bug at all. Although it could _technically_ count as a denial-of-service bug, Adobe had stopped accepting denial-of-service bug submissions if it did not involve stack or heap corruption. In the end, with admittedly slight disappointment, we decided to drop the crash and classify it as a bogus crash and a non-reportable bug.

# Afterword
While the interesting WinAFL crash ultimately did not result in us finding an actual bug, it was still really interesting to go through the whole debugging and analyzing process, through which we experienced a _huge_ range of emotions, and though it concluded with slight disappointment, attempting to get an actual crash was still fun, because I always love a good bug to analyze. I will keep the fuzzer running with new corpuses and constantly check and restart the fuzzer (at least until the end of my internship), and perhaps I might make another update if another interesting bug is discovered.

Thanks for reading.