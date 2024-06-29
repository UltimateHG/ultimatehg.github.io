---
id: 8
title: "STACK CTF 2020 - OSINT Challenge 2"
subtitle: ""Where was he kidnapped?""
date: "2020.12.09"
tags: "ctf, writeup, osint, open source intelligence, ctf blog"
---

## Foreword
This challenge is an OSINT, or Open Source Intelligence challenge, which means that it requires us to do research on the background of our target to retrieve information and eventually the flag. I like to call it "intense googling". Anyways, it's not too hard of a challenge, just an admittedly frustratingly painfully tedious question, so let's get straight into it.

You can download the challenge files from [here](https://drive.google.com/drive/folders/1FQvRousd8BP2TeegE7n9a1hDjUvMofa8?usp=sharing).

## Challenge Description
> The missing engineer stores his videos from his phone in his private cloud servers. We managed to get hold of these videos and we will need your help to trace back the route taken he took before going missing and identify where he was potentially kidnapped!

# The Base Information
We were provided with 3 videos. They provide some crucial information that will eventually lead us to the location. I will explain the most important moments of the 3 videos.

From the first video, at around 2 seconds, we get a clear view of the bus number, its terminal stop, its current stop (or rather, current neighbourhood district) as well as the fact that it's actually opposite an MRT station:

![](https://i.ibb.co/gDgWbVf/1.png)

From the second video, we can tell that 1) the stop is not close to the MRT (due to his caption) and 2) the stop has these 2 yellow pillars:

![](https://i.ibb.co/qWNF0Wd/2.png)

From the last video, we get a good look at the place that the target was resting moments before his kidnapping. We see that there are benches in front of him, that he is under shelter at a void deck and also that there is some sort of commmunity garden further in front. We can tell this is as HDB flat:

![](https://i.ibb.co/t2NMbkn/3.png)


# Further Analysis
For non-Singaporeans reading this, HDB flats are basically government housing and are very common around Singapore. There are some neighbourhoods that have community gardens, we can find the whole list on [NParks's website](https://www.nparks.gov.sg/gardening/community-gardens/visit-a-community-garden). Loading all the locations in List View, we can see that there are actually quite a lot of community gardens in Yishun, but we have to find one that's close to some yellow pillars and also close to a bus stop.

We can first take a look at the route of bus 117. We know that the our target's journey on bus 117 started from Yishun Ave 2 from the first video, and he's heading towards Punggol Int as his direction. So we're left with these possible stops:

![](https://i.ibb.co/hHCpkKJ/4.png)

Honestly, that's a lot of stops. But we just know that our target started his journey at a bus stop that was opposite the MRT station, so we can start looking from bus stop #59073, Opp Yishun Stn. We honestly just went into Google Street View and viewed the stops one by one, until we found a stop that looked like this:

![](https://i.ibb.co/1X42HTJ/5.png)

We spotted the yellow pillars, so we opened up this location in Google Maps to take a closer look:

![](https://i.ibb.co/KycKM6K/6.png)

# Community Garden Triangulation
Here we could see that this stop is right beside Block 870. This cluster of blocks seem to be missing Block 868, which is slightly weird (we found out Yishun didn't have a Block 869). Let's open up NParks's site again and Ctrl+F this general location:

![](https://i.ibb.co/rdxS9Mz/7.png)

We can see that there's a community garden very close to the bus stop at Block 868. We can safely assume that the unlabelled block on the map is in fact Block 868. So we now have most of the information needed:

1) The target alighted at the bus stop at Block 871.
2) He is looking at Block 868, so he could either be in Block 870, Block 871 or Block 868 itself, since he likely didn't walk far.

It's quite interesting, because Google Maps actually allows Street View in this particular small area:

![](https://i.ibb.co/P4RHnVG/8.png)

So we drop in and look around, and eventually we find this:

![](https://i.ibb.co/CBRcRv0/9.png)

You see those benches there? They look exactly like the ones in the video right before our target was kidnapped. It is also facing the correct direction, so this means that he was exactly under this block at this part of the void deck. We simply just panned the camera around, and:

![](https://i.ibb.co/Chgm7rV/10.png)

He was at the void deck of Block 870. We googled for the postal code of Block 870 and it turned out to be 760870, and thus we inputted the flag `govtech-csg{760870}`, and the challenge was solved.

# Afterword
Honestly, this challenge took longer than we're willing to admit, because we had to look through the bus stops one by one in street view until we found the one we needed. But everything before and after that were pretty generic OSINT stuff, where we have to make use of our knowledge of the area and of Singapore's roads, housing and transportation to help us pinpoint the location of the kidnapping. This was still a pretty fun challenge though, and finding the exact area in that second last screenshot brought a nice rush of excitement.

Thanks for reading.