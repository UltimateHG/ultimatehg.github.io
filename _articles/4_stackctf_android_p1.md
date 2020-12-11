---
id: 4
title: "STACK CTF 2020 - Mobile Challenges: Part 1"
subtitle: "Challenge 1: Contact Us! | Challenge 2: Subscribe!"
date: "2020.12.09"
tags: "ctf, writeup, mobile, android, android re, reverse engineering"
---

## Foreword
Over a 3-day period from 4-6th December, I participated in yet another CTF, but this time with a different team than the one I was most used to. Just a little background information for context: I also participated in Cyber Defenders Discovery Camp 2020 (CDDC 2020) with my team, Astronomia, and managed to clinch the 2nd runner up award. However, this time round half the members were busy so I teamed up with just one other Astronomia member and some highly promising juniors. I have to be honest, I was disappointed with my performance in the CTF, but hey, it was still a fun nonetheless. After all, that moment of euphoria when I press the submit button with a flag I just found and it successfully submits is something that never gets old. In this series of writeups, I will be explaining all the mobile (Android) challenges that I managed to solve and my thought process, as well as some bonus methods to solve (or "cheat") the flag. :)

This will be a multipart series as the writeups for some of the challenges are quite long. I will make the writeups as standalone as possible, meaning you won't need to read one writeup to understand another, so there could be some things repeated

Well, let's dillydally no further and jump right into the mobile challenges. I will be covering Challenge 1: Contact Us! and Challenge 2: Subscribe! in this first part of the writeups. These are 2 extremely short and simple challenges so the writeup won't go too much into detail, but I will still go as slowly as possible.

# Challenge 1: Contact Us!

## Description
> Looks like Korovax has exposed some development comment lines accidentally. Can you get one of the secrets through this mistake?

## Surveying Our Target
From the description of the challenge, we can tell that there are some comment lines or debug logs that we can try to access to solve the challenge. Our first step would be to open up the application and see what we can do. After opening the app, we are greeted with this home screen:

![](https://i.ibb.co/tYJW9Gj/1.png)

We see that there are 4 buttons, and in the bottom right corner there is a "Contact Us" button. That seems like a good place to start, since that is the name of the challenge. We tap into that and we get this screen:

![](https://i.ibb.co/KFPZYfn/2.png)

The textbox for "Contact Number" seems to have some text in there, and it says:
```
Sarah to Samuel: Cheat code is abracadabra. Remember to remove it before the CTF!
```

Huh, let's try inputting `abracadabra` into the textbox above for "name" then.

![](https://i.ibb.co/NSZtMcK/3.png)

Ah, we're greeted by a Toast saying: `The answer is already out if you have been checking something!`

Checking something... something... perhaps the debug log or the decompiled code? 

## Decompiling The APK
Let's decompile the APK with JADX-GUI, which is one of the most popular tools used to decompile Android APKs. We open the APK and are greeted with many many packages, but one of them is named `sg.gov.tech.ctf.mobile`, so that looks like where we should start. We need to find the view that we are looking at first. We expand that to find a package called `Contact`, so let's expand that, and sure enough, this is the class that controls the view we are looking at.

Clicking on it brings up the decompiled code, but we're mainly interested in the part that handles the first "Submit" button, which then leads us to this part of the code:
```java
((Button) findViewById(R.id.submit_button)).setOnClickListener(new a());
```

The `OnClickListener` for `R.id.submit_button` is set to a new object `a`, so let's look at this class. We are mainly interested in the `onClick()` component as that is what handles the logic of pressing the submit button:
```java
public void onClick(View v) {
  String enteredFlagString = ((EditText) ContactForm.this.findViewById(R.id.editText_name)).getText().toString();
    int toPad = 16 - (enteredFlagString.length() % 16);
    if (toPad != 16) {
      for (int i = 0; i < toPad; i++) {
        enteredFlagString = enteredFlagString + " ";
      }
    }
    int flagStatus = ContactForm.this.retrieveFlag2(enteredFlagString, enteredFlagString.length());
    if (flagStatus == 0) {
      Toast.makeText(ContactForm.this.getApplicationContext(), "The answer is already out if you have been checking something!", 0).show();
    } else if (flagStatus == 2) {
      c.a builder = new c.a(ContactForm.this);
      View view = LayoutInflater.from(ContactForm.this).inflate(R.layout.custom_alert, (ViewGroup) null);
      ((TextView) view.findViewById(R.id.RES_2131296615)).setText("Congrats!");
      ((TextView) view.findViewById(R.id.alert_detail)).setText(new f.a.a.a.a.b.a().a());
      builder.h("Proceed", new DialogInterface$OnClickListenerC0070a());
      builder.f("Close", new b());
      builder.k(view);
      builder.l();
      Toast.makeText(ContactForm.this.getApplicationContext(), "Correct Password!", 0).show();
    } else if (flagStatus == 1) {
      Toast.makeText(ContactForm.this.getApplicationContext(), "Password is wrong!", 0).show();
    } else {
      Toast.makeText(ContactForm.this.getApplicationContext(), "Something is wrong!", 0).show();
    }
}

```

We see that the part that we need to control is the particular variable called `flagStatus`. That is what decides whether or not the success code runs or we get "Password is wrong!" etcetera. And we also know that `flagStatus` is controlled by the return value of the function `retrieveFlag2()`, so let's take a look at how it's defined:
```java
public native int retrieveFlag2(String str, int i);
```

Looks like it's a native function. If you don't know what a native function is in Java, basically Java has a programming interface called the Java Native Interface (JNI), which allows for writing Java native methods and embedding the Java virtual machine into native applications. Simply put, a native function is a function that has been defined in a library compiled from languages such as C, C++ and assembly. JADX-GUI is unable to directly display native function definitions, but that doesn't matter in this case. Let's do a blind shot at catching the relevant log. I will try to `logcat` my device running the app with the tag `JNI` and see if that brings up anything:
```
C:\Users\User>adb logcat sg.gov.tech.ctf.mobile:V -s "JNI" *:S
--------- beginning of crash
--------- beginning of system
--------- beginning of main
12-11 14:25:07.156 10921 10921 D JNI     : Sarah to Samuel: You should see this with the cheat code. Now 'Give me the flag' will literally give you the flag. 
```

Ok, let's try inputting this into the "name" field instead:

![](https://i.ibb.co/qML09SM/4.png)

Bingo, that's the flag right there.

## Reverse Engineering?
But hey, that method seemed a bit guessy. What if our blind guessing did not hit any jackpots? Fret not, there is a more systematic way to approach this that actually requires no guessing at all. Remember earlier we talked about `native` functions? If we unpacked the APK we should be able to find the library that `JNI` is referencing for its `native` functions. For that, we will need to use something like APKTool to unpack the APK.
```
$ apktool d mobile-challenge.apk
```

This will unpack the APK into a folder called `mobile-challege`, and within there will be a `lib` folder. Inside this folder there should be folders containing libraries compiled for different architectures, but that isn't too important so let's just go with the `x86_64` architecture. We open up that folder and see our library `libnative-lib.so`. Let's fire up IDA and try to find the function that we're interested in:

![](https://i.ibb.co/7CCXxHr/5.png)

Right there, we see the call to `__android_log_print`, which is basically the native version of `Log.<priority>()`. We see that the priority is "3", the tag is "JNI" and the log message is:
```
"Sarah to Samuel: You should see this with the cheat code. Now 'Give me the flag' will literally give you the flag."
```

There, we have now achieved the same effect as before. Once again, we now simply put in "Give me the flag" into the "name" field and bingo.

# Challenge 2: Subscribe!

## Description
> Korovax would like to keep its users informed about the latest updates of COViD, and there's nothing better but to spam your emails!

## Surveying The Target
From the description, we can tell that we need to find some place in the app that allows us to do something related to subscribing. Coincidentally, from the previous challenge, our "Contact Us" view seemed to have another field below for us to enter our email to subscribe:

![](https://i.ibb.co/KFPZYfn/2.png)

Nice.

## JADX, once again
Now we're interested in the handling code for the "Subscribe" button. Within JADX-GUI, we see this line that sets the `OnClickListener` for the "Subscribe" button.
```java
((Button) findViewById(R.id.subscribe_button)).setOnClickListener(new b());
```

Ah, now we're interested in the `b` class. Let's take a look at its `onClick()` component, as that contains the logic for handling the pressing of the "Subscribe" button:
```java
public void onClick(View v) {
  if (ContactForm.this.check(((EditText) ContactForm.this.findViewById(R.id.editText_email)).getText().toString()) == 0) {
    c.a builder = new c.a(ContactForm.this);
    View view = LayoutInflater.from(ContactForm.this).inflate(R.layout.custom_alert, (ViewGroup) null);
    ((TextView) view.findViewById(R.id.RES_2131296615)).setText("Congrats!");
    ((TextView) view.findViewById(R.id.alert_detail)).setText("Well done!");
    builder.h("Proceed", new a());
    builder.f("Close", new DialogInterface$OnClickListenerC0071b());
    builder.k(view);
    builder.l();
    Toast.makeText(ContactForm.this.getApplicationContext(), "Flag is correct!", 0).show();
    return;
  }
  Toast.makeText(ContactForm.this.getApplicationContext(), "Flag is wrong!", 0).show();
}

```

We see that we need to satisfy the condition of the `if` statement in order to reach the success code. It calls a function `check()` on our input. Let's look at the definition for the function `check()`:
```java
public native int check(String str);
```

Oh, it is a `native` function as well. Similarly to before, after unpacking the APK with APKTool we find the relevant lib file and open it up in IDA, looking for the `check()` function:

![](https://i.ibb.co/0BcPBsL/6.png)

Well, that was surprisingly easy, our flag is right there: `govtech-csg{th3rE_15_nO_n0bIliTy_In_p0Vert7}`. Check basically just compares our input string to "`govtech-csg{th3rE_15_nO_n0bIliTy_In_p0Vert7}`", and if they match exactly it will return 0, which sets `flatStatus` to 0 and satisfies the condition for reaching the success code.

# Afterword
These were some pretty simple warmup challenges, so I hope you enjoyed the short part 1 to this long mobile challenge writeup series. The next few blog posts will go into quite a bit of detail on how to solve the remaining questions, so do read those if you're interested.

Thanks for reading.