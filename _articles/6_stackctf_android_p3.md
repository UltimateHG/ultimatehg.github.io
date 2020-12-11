---
id: 6
title: "STACK CTF 2020 - Mobile Challenges: Part 3"
subtitle: "Challenge 3: What's with the Search!"
date: "2020.12.09"
tags: "ctf, writeup, mobile, android, android re, reverse engineering"
---

## Foreword
This challenge comes after challenge 4, titled "True or false?". The numbering is slightly weird, hence in both writeups I might repeat some things already mentioned in the other just in case some people are only interested in one. This challenge was a pretty simple one, so let's get right into it.

DISCLAIMER: This challenge requires you to have already logged into the admin panel. If you don't know how to do that, please refer to the writeup for mobile challenge 4.

You can download the challenge file (mobile-challenge.apk) from [here](https://drive.google.com/file/d/1tf8-C1FKYBMKGICRKYe7abGGs3LX2i2m/view?usp=sharing).

## Challenge Description
> There is an admin dashboard in the Korovax mobile. There aren't many functions, but we definitely can search for something!

# Surverying The Target
The description for the challenge mentioned that "we can definitely search for something" within the admin dashboard, so we of course start by opening up the admin dashboard and taking a look:

![](https://i.ibb.co/xGHsrSQ/1.png)

We can see that there's a search bar at the top and also a search button. Tapping the search button with an empty or random input will produce a Toast that just reads "`Flag is wrong!`". That means that we likely have found the place that we have to input our flag in order to solve the challenge. Let's fire up JADX-GUI, which is a decompiler for APK files, to decompile our `mobile-challenge.apk` file.

# Decompiling The APK
We first need to look for the functions that we are interested in. The most obvious one to look for would of course be the screen(s) that we can directly see in the app. We are looking for a dashboard or a home page or something along those lines that is also related to admin, since the user login also likely has its own set of classes. We see a `sg.gov.tech.ctf.mobile` package, so let's start from there, expanding all the packages within this package:

![](https://i.ibb.co/T2BYQLd/3.png)

Looking through the classes, we can see that there is a class called `AdminHome` under the package `Admin`. This seems like a pretty good place to start. We want to look at the `onCreate()` function in order to figure out what the search bar is within the code, which would make things easier. We see the `onCreate()` as follows:
```java
public void onCreate(Bundle savedInstanceState) {
  super.onCreate(savedInstanceState);
  setContentView(R.layout.admin_home_activity);
  getWindow().setSoftInputMode(32);
  this.f2930c = (ImageButton) findViewById(R.id.button_submit);
  this.f2931d = (ImageButton) findViewById(R.id.network);
  this.f2932e = (EditText) findViewById(R.id.editText_enteredFlag);
  this.f2934g = (CalendarView) findViewById(R.id.calendar_view);
  this.f2933f = (TextView) findViewById(R.id.date);
  this.f2931d.setOnClickListener(new a());
  this.f2934g.setOnDateChangeListener(new b());
  this.f2930c.setOnClickListener(new c());
}
```

We see an `EditText` being assigned to `findViewById(R.id.editText_enteredFlag)`, so that means that that's likely the search bar where we're supposed to enter our flag. There is also another `ImageButton` assigned to `findViewById(R.id.button_submit)`, so seeing as there are no other submit buttons, that's likely referring to the search button itself. The `OnClickListener` for the submit button, `f2930c`, was set to `new c()`, so let's take a look at the class `c` to see what it does. `c` extends `View.OnClickListener`, and the constructor is just a default constructor. However, it contains a custom `onClick()` function:
```java
public void onClick(View v) {
  AdminHome adminHome = AdminHome.this;
  adminHome.f2932e = (EditText) adminHome.findViewById(R.id.editText_enteredFlag);
  if (AdminHome.this.b(AdminHome.this.c(AdminHome.this.f2932e.getText().toString())).equalsIgnoreCase(AdminHome.this.f2929b)) {
    c.a builder = new c.a(AdminHome.this);
    View view = LayoutInflater.from(AdminHome.this).inflate(R.layout.custom_alert, (ViewGroup) null);
    ((TextView) view.findViewById(R.id.RES_2131296615)).setText("Congrats!");
    ((TextView) view.findViewById(R.id.alert_detail)).setText("Add govtech-csg{} to what you found!");
    builder.h("Proceed", new a());
    builder.f("Close", new b());
    builder.k(view);
    builder.l();
    Toast.makeText(AdminHome.this.getApplicationContext(), "Flag is correct!", 0).show();
    return;
  }
  Toast.makeText(AdminHome.this.getApplicationContext(), "Flag is wrong!", 0).show();
}
```

There are some other functions that are being called, but we can see that our most important line is the condition check in the if statement: `AdminHome.this.b(AdminHome.this.c(AdminHome.this.f2932e.getText().toString())).equalsIgnoreCase(AdminHome.this.f2929b)`. This compares the userinput passed into several nested functions against a previously defined string `f2929b`. Let's take this one step at a time. Firstly, we look at the left side of the compare, which calls the functions `b()` and `c()`, so let's take a look at those:
```java
public final String c(String enteredFlagString) {
  if (!enteredFlagString.contains("govtech-csg{")) {
    return enteredFlagString;
  }
  String result = enteredFlagString.replace("govtech-csg{", BuildConfig.FLAVOR);
  return result.substring(0, result.length() - 1);
}

public String b(String toHash) {
  try {
    MessageDigest digest = MessageDigest.getInstance("SHA-1");
    byte[] bytes = toHash.getBytes(SQLiteDatabase.KEY_ENCODING);
    digest.update(bytes, 0, bytes.length);
    return bytesToHex(digest.digest());
  } catch (NoSuchAlgorithmException e2) {
    System.out.println("Algorithm not recognised");
    return null;
  } catch (UnsupportedEncodingException e3) {
    System.out.println("Something is wrong. Like really.");
    return null;
  }
}
```

# Linking Everything Together
Ah, so all `c()` does is it accepts and input string and strips "`govtech-csg{`" (it is a bit weird though, it doesn't remove "`}`" from the back). `b()` on the other hand would take in an input and the key line here: `MessageDigest digest = MessageDigest.getInstance("SHA-1");` tells us that it wants to encode something with `SHA-1`. Going further down, we see that the input passed into `b()` is converted into a `byte` array and then passed into `digest`. This means that what `b()` does is accept a string input, encrypts it with `SHA-1` and returns the result as a string. Now, let's link it back to the `onClick()` that we were analysing earlier.

This means that the left side of the compare is a `SHA-1`-encrypted string of the user's input, and it's trying to do a simple compare against the string `f2929b`. We're now halfway there, let's take a look at `f2929b`:
```java
public String f2929b = getPasswordHash();

public native String getPasswordHash();
```

It is assigned to the return value of `getPasswordHash()`, which is defined as a `native` function. Hmm, what is a `native` function? Basically, Java has a programming interface called the Java Native Interface (JNI), which allows for writing Java native methods and embedding the Java virtual machine into native applications. Simply put, a `native` function is a function that has been defined in a library compiled from languages such as C, C++ and assembly. Now this is something we are unable to see directly from JADX-GUI, so we need to do something to also unpack the APK for us. This can be done easily with a popular tool called APKTool. APKTool decompiles Android code into the smali format, but also unpacks the APK so we will be able to see any libraries that it uses. The smali code will not be needed to solve this challenge so I will not be covering that. Let's use APKTool to decompile `mobile-challenge.apk`.
```
$ apktool d mobile-challenge.apk
```

This will decompile and unpack the APK into the folder `mobile-challenge`. We can see a `lib` folder, and clicking into it reveals 4 more folders, but they just represent libraries compiled for different architectures, so I'll just use the `x86_64` libraries. I open up `libnative-lib.so` in IDA x64 and search for the function `getPasswordHash()`, and sure enough, it's there.

I decompile the function and we're left with this:

![](https://i.ibb.co/R0kfWYZ/3.png)

We see that it calls a sub function, but from what I can see this function contains this interesting part:

![](https://i.ibb.co/cKqh3sV/4.png)

This string, `b7c1020edc5d4ab5ce059909f0a7bd73b3de005b`, is exactly in the format of SHA-1. This lead me to believe that what this function returns is just `b7c1020edc5d4ab5ce059909f0a7bd73b3de005b` as a string. This means that our comparison target `f2929b` is likely just the string `b7c1020edc5d4ab5ce059909f0a7bd73b3de005b`. Now we already have all the tools needed to finish the challenge.

The if statement compares a `SHA-1`-encrypted user input to `b7c1020edc5d4ab5ce059909f0a7bd73b3de005b`, and if true it will print the success message. We just need to decrypt `b7c1020edc5d4ab5ce059909f0a7bd73b3de005b`:

![](https://i.ibb.co/tD70z0F/5.png)

Let's put it into the app just to be sure:

![](https://i.ibb.co/c8SGJfn/6.png)

The flag for this challenge is thus `govtech-csg{qqww1122}`.

# Afterword
This was a relatively easy challenge that didn't require much Android knowledge, except knowledge of the tools to use to decompile the APK, but that is easily googleable. Of course, it still requires basic knowledge for reverse engineering as well as how to link all your findings back to the main problem at hand. This was, with no doubt, easier than the challenge required to reach this screen: Challenge 4 - True or false?

Thanks for reading.