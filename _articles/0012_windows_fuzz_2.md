---
id: 12
title: "Fuzzing Windows Stuff: WMF"
subtitle: "2. Windows Media Foundation: Metadata"
date: "2021.04.18"
tags: "c++, fuzzing, windows, windows media foundation"
---

## Foreword
It's definitely been some time since my last post considering this was meant to be a multiple part post series, but I've been quite occupied with compulsory military service (yep.) so I haven't had access to my computer for quite a while, but now that I'm back for a very short time I might as well write up more on my WMF research. Last time round it was on fuzzing the MP3 parser, so this time I will talk about something somewhat related but also quite different, which will be file metadata. All media files have metadata that can be attached to them which will be parsed by WMF and displayed in many different places (like the generic file information you can see in windows explorer, file properties window etc.) and hence that can also be an attack surface. Similarly to all my posts, there may be some points that I will repeat here in case not everyone has read the previous post(s) in the series, so please bear with me on that.

# Windows Media Foundation And Metadata
Windows Media Foundation (WMF) is a platform on Windows that allows developers and consumers to play, convert, record and mess around with a wide range of media files. But this platform also happens to handle most if not all the media-parsing that happens in Windows, including the metadata of media files. It is actually quite fascinating, because Windows has changed the way it parsed metadata since Windows Vista, but in this post I will just be covering on metadata parsing from Windows 7 onwards.

Every media-related file in Windows (7 and later) makes use of an internal object called an `IPropertyStore` to store file metadata, and it is no different for media files. WMF is able to read the `IPropertyStore` object attached to any media file and get retrieve any value, which means that we would be able to harness it separately without needing to ever read the media file or do anything with the media file. And therefore, we would want a harness that simply opens a media file, retrieves its `IPropertyStore`, reads the values and attempts to print all of them out. Once again, we would dive into [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/win32/medfound/shell-metadata-providers) to try to understand how all the objects interact with one another and ultimately how we could achieve the our objective to retrieve the `IPropertyStore` object.

# Creating The Harness
As with creating all other harnesses, we should try to split our initialization function (usually our `main` or `wmain`) from our fuzzing function. Using [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/win32/medfound/shell-metadata-providers) as a guideline, we know that we need to initialize the COM library in order to run anything related to WMF, and from past experience we also know that the workload of `CoInitialize()` is too great to be used within the fuzzing function, so we will be initializing the COM library within the main function, extracting the file path inputted, and then running the fuzzing function, which we will call `fuzzme()`. We end up with a barebones `wmain` function as such:
```c++
int wmain(int argc, wchar_t* argv[])
{
    if (argc != 2)
    {
        printf("arguments: input_file\n");
        return 1;
    }

    HRESULT hr = S_OK;

    // Initialize the COM library.
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED | COINIT_DISABLE_OLE1DDE);

    // Call fuzzme
    if (SUCCEEDED(hr))
    {
        if (SUCCEEDED(hr)) {
            WCHAR absPath[MAX_PATH];
            GetFullPathName(argv[1], MAX_PATH, absPath, NULL);
            hr = fuzzme(absPath);
        }
    }
    CoUninitialize();

    return SUCCEEDED(hr) ? 0 : 1;
}
```

Also, fuzzing a 32-bit application on a 64-bit system always has some weird stack alignment problems, so we will be using the stack alignment mitigation that was mentioned all the way back in our Adobe research to help align the stack so that we would have a lot less bogus crashes:
```c++
size_t a = 0;
if (((size_t)&a) % 8 != 0) {
    alloca(4);
}
```

Next, we would need to create the fuzzing function, and this one is actually really simple as well, because all we need to do is take in the absolute file path as obtained from the `wmain` function earlier, read the file and retrieve its `IPropertyStore` object, which can be done with 2 quick lines of code:
```c++
hr = SHGetPropertyStoreFromParsingName(file, nullptr, GPS_READWRITE, IID_PPV_ARGS(&pProps));
CHECK_HR(hr, "Failed to load into IPropertyStore.");
```

After testing for a bit, we also realized that it wasn't important to attempt printing out the metadata as it didn't really affect whether or not our harness would crash, hence at this juncture we could already just call `SafeRelease()` and our `fuzzme()` function is complete.

# Fuzzing And Preliminary Results
Fuzzing with this harness was quite an emotional rollercoaster, as only a day into the fuzzing and we were already getting some promising hangs. Opening up those files with Windows Explorer caused Explorer to go unresponsive for quite a period of time, but unfortunately as long as Explorer was left alone, it would not crash and would still eventually load the metadata. However, after about a week of fuzzing, we actually managed to uncover some interesting things, which I think I cannot be talking much about yet, but do look forward to a post in the future that might discuss this further.

Either way, fuzzing this seemed a lot more practical than fuzzing MP3/MP4 parsing to us, as parsing media had too many domains available as well as too many variables that we were unable to control precisely (largely due to the fact that we could not even understand it fully ourselves), so in the end we decided to focus on fuzzing the metadata instead.

# Afterword
This is quite a short post as there really was not much that was needed to be done in order to fuzz the metadata of media files, and figuring out many things as we went along trying to fuzz WMF had been an enjoyable experience. In the next post, I would likely be moving off WMF and talking about some other attack surfaces. I was also unable to share certain information in this post, so I apologize for the short final chapter of the post, but I promise that if I'm able to, I would share more about it in the future.

But that's all for now. Thanks for reading.