---
id: 11
title: "Fuzzing Windows Stuff: WMF"
subtitle: "1. Windows Media Foundation: MP3"
date: "2021.03.12"
tags: "c++, fuzzing, windows, windows media foundation, winafl, vulnerability research"
---

## Foreword
Well, I have been gone for quite a while (again), I really should set a better schedule for writing these posts. Over the past months, I have been doing quite a bit of fuzzing with different Windows components, including but not limited to Windows Media Foundation, Windows Shortcuts (LNK) and Microsoft XML (MSXML). This post will be the first in a series where I will explore and dicuss the different harnesses I created for each of the above mentioned components as well as fuzzing results, if any, that I have obtained.

# Windows Media Foundation
Windows Media Foundation (WMF) is a platform on Windows that allows developers and consumers to play, convert, record and mess around with a wide range of media files. According to Microsoft, it would allow us to "embrace the new wave of premium content with enhanced robustness, unparalleled quality, and seamless interoperability." Sheesh. But having such a large publicy available library perform so many tasks always means that there would be a lot of bugs, so as a security-researcher-in-training, of course what I thought was: "Can I crash it?" So I worked with another intern and we tried to harness different parts of Windows Media Foundation in hopes of fuzzing some crashes. One of the first we worked on was MP3 parsing with WMF.

This was pretty interesting because throughout my years of learning just software engineering I have never really dug deep into media files, so I never used to see them as a interoperable bytestream but instead as just individual media objects, and learning to use WMF made me realize how interesting media files were.

The way we would always approach creating a harness was first getting a bare minimum executable that would not crash and would correctly output what we wanted to parse, then we would strip the output functions that we could remove and separate all the parsing code from the initialization code to reduce the load on the fuzzer and also get more executions per second. When learning to create a harness with WMF, we initially just followed the different code samples available in Microsoft's documentation, but we realized afterwards that we were hurting our fuzzer's performance quite a bit because we weren't actually doing bare minimum parsing. I'll talk more about this in the next section.

Starting with MP3s was also beneficial to us as there were less media streams to worry about, and if we could get our MP3 parser to work then it would be really easy to make an MP4 (or any other video type) parser as the code wasn't too much different.

# Creating The Harness
We created the harness initially by following Microsoft's documentation, many (if not most) of which actually made use of Microsoft's own interface for media parsing (`MediaSource`, `IMFSourceReader` etc.) as seen [here](https://docs.microsoft.com/en-us/windows/win32/medfound/player-cpp) and [here](https://docs.microsoft.com/en-us/windows/win32/medfound/audio-clip-sample) just for some quick examples.

This would work under normal circumstances, if all we needed was just an application that could parse and playback media files it would all be fine and dandy, but this was actually not very good for fuzzing (we used WinAFL and some other variants). At one point, our application had to deal with some weird service, and the fuzzer wasn't able to end the service in order to restart the application. However, we decided that we could keep the interface as long as it didn't interfere with the fuzzer's processes.

Eventually, after tinkering around, we settled with something like this for our fuzzing function:
```c++
HRESULT fuzzme(const WCHAR* file) {
    HRESULT hr = S_OK;
    IMFSourceReader* pReader = NULL;
    IMFByteStream* pByteStream = NULL;
    IMFMediaType* pAudioType = NULL;

    //Create Source Reader
    //hr = MFCreateSourceReaderFromURL(file, NULL, &pReader);
    hr = MFCreateFile(MF_ACCESSMODE_READ, MF_OPENMODE_FAIL_IF_NOT_EXIST, MF_FILEFLAGS_NONE, file, &pByteStream);
    CHECK_HR(hr, "Failed to open input file.");

    hr = MFCreateSourceReaderFromByteStream(pByteStream, NULL, &pReader);
    CHECK_HR(hr, "Error creating source reader from byte stream");

    hr = ConfigureAudioStream(pReader, &pAudioType);
    CHECK_HR(hr, "ConfigureAudioStream failed.");

    //Call ProcessSamples()
    ProcessSamples(pReader);

done:
    SafeRelease(&pByteStream);
    SafeRelease(&pReader);
    return hr;
}
```

# Running The Fuzzer
There was one interesting hiccup that we ran into: the dll we were trying to harness never gets loaded. Weird, isn't it? Debugging in WinDBG showed that it does get loaded, but when running WinAFL in debug mode, we don't see it in the list of modules loaded. We had to dig around quite deep for this one, and we found out that Windows actually loads some of the dlls into a deffile.dll and loads that instead of loading the dlls individually, so we decided to try setting deffile.dll as our coverage module instead, and it ended up working.

In the end, we just ran WinAFL with the following command:
```
afl-fuzz -i in -o out -t 120000+ -M master01 -- -log_exception -coverage_module deffile.dll -target_module wmf_mp3.exe -target_method fuzzme -covtype edge -fuzz_iterations 2000 -persistence_mode in_app -- wmf_mp3.exe @@
```

We got some crashes through the fuzzer over slightly longer than a week of fuzzing, but unfortunately most of them weren't worthwhile crashes. To triage the crashes, I just coded a quick python program that opens pipes and runs the harness on every file in a predetermined output directory (of the fuzzer). There was one particular crash that was actually pretty cool because it showed up as heap corruption, but Groove Music actually displayed an "Insufficient Memory" error which meant they were able to catch the exception, though it still is pretty cool that the fuzzer managed to find something that could've worked in old versions of WMF.

# Afterword
This was the first type of harness that we attempted, and in the end we decided to spend a lot more time on the other harnesses so we didn't explore much beyond just fuzzing for about a week because we felt that fuzzing worked better on shortcut files and metadata, which I will also be covering in the following posts. It was pretty refreshing to work on Windows-related fuzzing, and being able to code in C++ instead of C saved a few nights of headaches (though C++ comes with its own set of frustrations). I will probably explore this a lot more on my own and will try to understand the code base better in the future.

But for now, thanks for reading.