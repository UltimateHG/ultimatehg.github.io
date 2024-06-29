---
id: 21
title: "Windows Heap Manager - An Exploration"
subtitle: "Personal Notes from Corelan Windows Heap Exploitation Workshop"
date: "2024.05.31"
tags: "windows heap, windows, heap, exploit, vulnerability research"
---

## Foreword

It's been a while since I've had some time to sit down and churn through a blog post, so here we go. 2 months ago, I was lucky enough to be provided an opportunity to attend Corelan's Windows Heap Exploitation Workshop as part of the SINCON 2024 workshops.

Personally I have always wanted to try learning the Windows Heap, since my CTF specialization in pwn has taught me a lot about the Linux Heap. And yet, the resources on the Windows Heap tend to be extremely scattered and hard to access, most of which is either too daunting (imagine reading through Microsoft's entire Windows documentation) or locked behind insane course paywalls (upwards of 10 grands!). While the sentiment is understood, as a student with basically no income it's hard for me to find the time or money to attend such courses. As such, I am extremely grateful to Div0 and Corelan for providing me with this opportunity.

With all that said, I thought I wanted to at least do a blogpost about the Windows Heap to try to help out others who might be in the same situation as me. **For obvious reasons, I will not be directly disclosing the exploit-based content of the course,** but I will talk about the way the Windows Heap operates as well as some personal points of interest.

Hence, this post will be more of just me yapping about the implementation of the heap rather than specific technical examples/walkthroughs like my other technical posts, as that would tread too much into the territory of leaking the course.

# Windows Heap - Mitigations

All pwn players know that in Linux, many mitigations exist such as PIE, Stack Canary, Full RELRO etc, and it is similar in Windows. There are 2 primary mitigations present in the Windows Heap that I will talk about - ASLR and DEP.

## ASLR

ASLR works pretty much the same as on Linux in the broad definition: it provides address space randomisation to executables (exe) and DLLs.

In the same vein, exploitation would require return-oriented programming (ROP), in mostly the same way it works on Linux pwn. ASLR is enabled by default during compilation of Windows executables and DLLs.

In memory during the runtime of any application, there is usually:
1. Executable
2. Loaded DLLs
3. Stack
4. Heap
5. Process Environment Block (PEB)
6. Thread Environment Block (TEB)

What ASLR does is that it randomizes the high bytes of the module base address, much like ASLR and PIE does on Linux as well. Modules are always **page-aligned**. ASLR applies to everything listed above. There is one key difference though - OS modules are only randomized at boot, whereas application modules are randomized per new instance.

The different ways to exploit this include but are not limited to:
- Avoiding ASLR: Use non-ASLR moduels or force predictability
- Partial overwrite: Take advantage of an existing pointer - partial redirection possible without knowing randomized bytes
- Bruteforce: Also known as heap spraying, or heap fengshui
- Memory leak: This works the same as on Linux - information leak can lead to trivial computation of actual addresses

## DEP

Data Execution Prevention (DEP) is basically no-execution (NX). DEP prevents execution of code directly from random parts of the stack, which prevents us from directly placing and executing shellcode. Instead, similarly to ASLR, we will have to perform ROP.

With some reference to [Microsoft's documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/bcdedit--set):

By default on all client OS, core services, executables that are compatible and apps that activate DEP will use the OptIn strategy i.e. DEP is always turned off except for the aforementioned processes.

By default on all server OS, DEP is always turned on except for whitelisted apps that can be set by an admin user.

As for the different ways to bypass such a mitigation, it is also similar to on Linux:
- ROP Chain: ROP to specific functions with executable params can basically completely bypass DEP
- pushad/retn: This is the type of ROP chain created by Mona (Corelan's automated Win7 heap tool)

# Windows Heap - Heap Management

There are 2 "types" of heap present in Windows: **NT Heap** and **Segment Heap**, where the NT Heap, albeit being an abbreviation for "New Technology", is the "legacy" heap used by Windows 7 and the Segment Heap is the "new" heap that was introduced in Win7+.

There are 2 kinds of memory management - from the Kernel and from UserLand. For the kernel, it is managed through ntoskrnl.exe that performs virtual memory management operations together with other kernel-based services. For the user, it is the usual stack and heap that everyone is familiar with. The stack is a fixed-size piece of memory used for local variables etc. and cannot grow, whereas the heap is "managed" memory that can grow but requires proper reallocation and freeing of old memory blocks.

## Alloc - NT Heap

This is the heap that Windows 7 implemented. This heap is organized into heaps, segments and chunks. Heap information is stored in the PEB (see: ASLR).

This might get a little confusing so stay with me for a bit.

For a high-end developer, the common usages of heap are (but not limited to):
- Kernel32.dll
    - Create a new heap for your own process - don't reuse system heap!
    - HeapCreate/HeapDestroy: create/remove a heap
    - HeapAlloc/HeapFree: allocate or free a chunk
    - HeapReAlloc: change size of existing allocation (memcpy then free original)
    - HeapLock/HeapUnlock: control mutual exclusion to heap operations
- C runtime (msvcrt.dll)
    - malloc/free, but it still often is just a wrapper around HeapAlloc/HeapFree
- C++
    - “new” operator: new instance usually begins with heap allocation (usually HeapAlloc)
- ntdll.dll
    - RtlAllocateHeap
    - RtlFreeHeap
    - *Not all reallocs go to RtlReAllocateHeap, but eventually alloc/free will go through RtlAllocateFree*

GetProcessHeap() gets address of Default Process Heap. Application can allocate memory chunks through Windows Heap Manager (RtlAllocateHeap) or directly from the Virtual Memory Manager (VirtualAlloc). Heap is a fixed-size memory container.

The heap is sort of structured like in Linux:
- Heap starts from HEAPBASE
- Right after HEAPBASE, there is the heap header which contains heap metadata
- HEAPBASE -> Heap Header + Segment 1 Header + Segment 1
- The segment is 1 massive block (storage), and gets consumed for heap allocation
- Segment header contains a list of all its chunks

The NT Heap is split into 2 distinct allocators - the Front-End Allocator (FEA) and the Back-End Allocator (BEA). The heap header contains the information about the FEA and BEA. FEA is also otherwise known as the Low-Fragmentation Heap (LFH).

Think of the FEA loosely like the tcache - same-sized pre-reserved heap segments. This will be used for commonly allocated variables, i.e. chunks of 0x40 are allocated many times -> it will be moved to be handled by the FEA.

The BEA consists of a massive heap segment ready to be "consumed" by the application. Consumption of heap memory is counted in blocks, and blocks are counted in multiples of 8. Hence for example, allocating 11 bytes would consume 2 blocks If segment fills up, a new segment will be created and added to the segment list - pointer to segment list is stored in heap header. The heap header contains a list of segment addresses and every segment has their own header. Every allocated user "chunk" contains an 8-byte header at the start of the chunk. Every chunk contains a FREE flag, the size of the previous chunk and its own size.

For allocs that are too big in size, memory will be used directly via VirtualAlloc and will be a standalone chunk that does not reside within any specific segment. These are called VirtualAlloc Blocks (VAB). VABs are in a doubly-linked list - they contain a forward pointer, backward pointer in their headers. The heap header metadata (see previous paragraph on the heap header) contains the address to the first element in the VAB list.

## Alloc - Segment Heap

There is a new type of "opt-in" heap available in Windows 8+ which is the segment heap. I will not talk too much about the segment heap as it is much more convoluted to me in terms of exploitation.

In the Segment Heap, segments are no longer non-biased. Segments are divided into different parts that will hold allocation of different sizes.

The heap is separated into these types of allocations:
1.	Low Fragmentation Heap (LFH)
2.	Variable Size Allocation (VS)
3.	Backend Allocation
4.	Large Blocks Allocation

For storage:
1.	Backend Blocks (LFH, VS, Backend Allocation goes here)
2.	Large Blocks (Large Blocks Allocation goes here)

There are randomly sized blocks in between chunks, until a large size is requested. Detailed information on segment heap internals can be found in this [BlackHat talk by MV Yason](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf).

## Free - NT Heap

I will only be talking about free mechanism for NT Heap for the same reason as mentioned in the previous section. The talk linked above contains information for the free mechanism on the Segment Heap as well, for anyone that's interested.

In the NT Heap, all free chunks are part of the **FreeLists** (not a grammatical typo). FreeLists is a doubly-linked list like bins in linux, maintaining its metadata and storing its forward and backward pointer in the user data portion. FreeLists orders its chunks in order from smallest to largest, and the first and last node will always link back to the heap header. The heap header contains a forward and backward pointer that links to and from the first/last chunk in the freelists.

From Windows Vista onwards, ListHints were added to the heap header: it is effectively a table that keeps track of a forward pointer pointing to the **1st free chunk** of specific sizes. For example, 0x10-byte chunks, 0x18-byte chunks etc.

Upon freeing, the BEA checks if the freed chunk is adjacent to other free chunks. If it is, then coalescing happens and **ListHints**, **FreeLists** are updated accordingly.

BEA groups chunks of different sizes into different “buckets”, everytime a new alloc is done BEA adds a count to the bucket. Upon any free within a bucket, that bucket’s count is reset to 0.

This is how the BEA keeps track of the "most popular" chunks in order to send chunks to the FEA. FEA uses pre-defined chunks inside segments, of the "popular" sizes. The LFH (FEA) is a LIFO queue of chunks, where they won’t coalesce nor split.

Freed chunks goes to BEA if it’s BEA-allocated, and FEA if it’s FEA-allocated - FEA is effectively a data structure by itself, where its own storage is within chunks inside segments. Once a bucket is marked for FEA, it is one-way/non-reversible, i.e. buckets that are marked and handled by FEA will never go back to being handled by BEA.

And with this, I would like to conclude this blog post. Thank you to anyone that read until here - Windows Heap is a colossal subject.

## Afterword

I will not be delving into the specifics for the exploitation tactics nor analysis of exploits due to the reason stated in my foreword. However, I hope to have been able to write a somewhat informative blog post for anyone who is interested in the Windows Heap but never managed to find substantial yet concise information on the subject. Afterall, not many people like going through massive backlogs of Microsoft documentation or have the money (less sponsored) to attend ten-thousand-dollar workshops.

The information written here is a mix of facts presented by Microsoft that I learned during the workshop as well as my own interepretation of the things I have learnt, so there could very well be errors within my understanding. Please do not take this as gospel and always do your own research if you wish to further investigate this topic!

And with that, I hope I had helped or entertained you in some way. As always, thanks for reading.