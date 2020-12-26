---
id: 7
title: "STACK CTF 2020 - Mobile Challenges: Part 4"
subtitle: "Challenge 5: Welcome to Korovax Mobile!"
date: "2020.12.09"
tags: "ctf, writeup, mobile, android, android re, reverse engineering"
---

## Foreword
This challenge actually has 3 ways of solving it, one is a more "basic" way while the other 2 are slightly cheesy, I will be going through all 3 methods of solving the challenge, then I'll reveal which method I used to solve the challenge. This writeup may contain some duplicate information from other mobile writeups, but this is to cater to those that only wish to read the writeup for this challenge. I'll do this step by step and try to explain as clearly as possible so that it can be understood without much background knowledge :)

You can download the challenge file (mobile-challenge.apk) from [here](https://drive.google.com/file/d/1tf8-C1FKYBMKGICRKYe7abGGs3LX2i2m/view?usp=sharing).

## Challenge Description
> To be part of the Korovax team, do you really need to sign up to be a member?

# First Steps
In order to start solving the challenge, we need to first understand what we have to attack. The challenge description says "do you really need to sign up to be a member?", so we can assume it has somethign to do with logging in. Let's first open the app and take a look at the home screen:

![](https://i.ibb.co/tYJW9Gj/1.png)

We can see that there is a user login page. Let's tap into that. We are greeted by this screen:

![](https://i.ibb.co/Tgf4cZH/2.png)

Playing around a bit, we realize that the "Sign Up" fragment is useless as the "Sign Up" button is just a dead button that does nothing. Tapping "Forget Password?" just creates a Toast that says: `You can't handle the truth!`. This could be an SQL injection challenge, but we need to make sure before we try to attack anything. Let's try decompiling the APK.

# Decompiling The APK
There are many ways to approach decompiling the APK, but two of the most popular ways are: APKTool to decompile the APK into smali code, and JADX-GUI, to provide a pseudo-code presentation of what the original functions and classes could have been.

Both will come in handy, but for this particular method we will only need to use JADX-GUI to look at the decompiled code. Let's fire up JADX-GUI and open the APK file. We are immediately greeted with many many packages, but we can find a package labelled `sg.gov.tech.ctf.mobile` package, so let's start from there, expanding all the packages within this package:

![](https://i.ibb.co/T2BYQLd/3.png)

We can see that under the `User` package, there is a class named `AuthenticationActivity`. This looks promising, so let's decompile it and see what it does. We can see many functions being defined, but we are interested in the `onCreateView()` function, as it is the function that assigns our view components to its corresponding object in the code. We can these lines within the function:
```java
this.f2885b = (EditText) root.findViewById(R.id.username_input);
this.f2886c = (EditText) root.findViewById(R.id.password_input);
this.f2887d = (Button) root.findViewById(R.id.login_button);
```

Okay, that means that the login button is named `f2887d`, and we can take a look at its `onClick()` listener:
```java
this.f2887d.setOnClickListener(new b(root, dbhelper));
```

A new object `b` is created with the params `root` and `dbhelper`. `root` is just to pass the `ViewGroup` over so we can ignore it for now, we are more interested in the second param `dbhelper`. From within the `onCreateView()` function, we can see the initialization of `dbhelper` as such:
```java
f.a.a.a.a.c.a dbhelper = f.a.a.a.a.c.a.c(root.getContext());
SQLiteDatabase db = dbhelper.getWritableDatabase(c.a.a.a.a(-10177538076600L));
if (!dbhelper.b(c.a.a.a.a(-10203307880376L), db)) {
  dbhelper.a(db);
}
```

It is a `f.a.a.a.a.c.a` object. We can also look at the class `b` as we also need that to try to solve the challenge:
```java
public final ViewGroup f2890b;
public final f.a.a.a.a.c.a f2891c;

public b(ViewGroup viewGroup, f.a.a.a.a.c.a aVar) {
  this.f2890b = viewGroup;
  this.f2891c = aVar;
}

public void onClick(View v) {
  String password = a.this.f2886c.getText().toString();
  if (password.contains(c.a.a.a.a(-9421623832504L))) {
      Toast.makeText(this.f2890b.getContext(), c.a.a.a.a(-9516113113016L), 0).show();
  }
  if (this.f2891c.e(c.a.a.a.a(-9726566510520L), password, this.f2891c.getReadableDatabase(c.a.a.a.a(-9700796706744L))).matches(c.a.a.a.a(-9748041347000L))) {
    c.a builder = new c.a(this.f2890b.getContext());
    View view = LayoutInflater.from(this.f2890b.getContext()).inflate(R.layout.custom_alert, (ViewGroup) null);
    ((TextView) view.findViewById(R.id.RES_2131296615)).setText(c.a.a.a.a(-9842530627512L));
    ((TextView) view.findViewById(R.id.alert_detail)).setText(c.a.a.a.a(-9885480300472L));
    builder.h(c.a.a.a.a(-9997149450168L), new DialogInterface$OnClickListenerC0066a());
    builder.f(c.a.a.a.a(-10031509188536L), new DialogInterface$OnClickListenerC0067b());
    builder.k(view);
    builder.l();
    return;
  }
  Toast.makeText(this.f2890b.getContext(), c.a.a.a.a(-10057278992312L), 0).show();
}
```

Now, we notice there are some wrapper functions within, one such being `c.a.a.a.a()`, but we can leave that aside for now, as what's more important is the `f.a.a.a.a.c.a` class, which we now see appear twice already. We can open up the class in JADX-GUI to take a look at it as well.
```java
public class a extends SQLiteOpenHelper {
```

This first line already tells us that the class `f.a.a.a.a.c.a` likely helps to query a database, which means this question is likely an SQL injection challenge. Looking down, we can see that there are many database queries being carried out, which confirms that this is infact an SQL injection challenge. There is one particular portion which is quite interesting:
```java
public void a(SQLiteDatabase sqLiteDatabase) {
  sqLiteDatabase.execSQL("INSERT INTO Users VALUES ('user', 'My_P@s5w0Rd_iS-L34k3d');");
}
```

A query that adds a user with username `user` and password `My_P@s5w0Rd_iS-L34k3d`? Of course we have to try it out.

![](https://i.ibb.co/rxff1GJ/4.png)

Ah, it just spawns a Toast that reads: `Do you think it will be that easy? Muahaha`. Curses, of course they wouldn't let the challenge end right here. Let's continue looking at how to tackle the challenge.

Since we know it is an SQL injection challenge, let's try giving it the most basic SQL injection password input. We will login with the username `user` and the password `' OR 1=1 -- ` (including the space at the end!):

![](https://i.ibb.co/M9X75YK/5.png)

Well, that worked. We now have the flag.

# Harnessing The Wrapper
"Oh no! What if I don't know how to do SQL injection?"

No worries, this challenge has got you covered. Let me introduce to you -- the second way of solving this challenge, by simply harnessing the wrapper function.

Remember earlier we noticed that a particular function `c.a.a.a.a()` has been called many times? It always accepts a `long` as its input, and from initial code analysis we can tell that it should return a string, as its return value is put directly into `setText()` and `Toast.makeText()`, which accept string inputs. Let's have a quick refresher of the `onClick()` function:
```java
public void onClick(View v) {
  String password = a.this.f2886c.getText().toString();
  if (password.contains(c.a.a.a.a(-9421623832504L))) {
    Toast.makeText(this.f2890b.getContext(), c.a.a.a.a(-9516113113016L), 0).show();
  }
  if (this.f2891c.e(c.a.a.a.a(-9726566510520L), password, this.f2891c.getReadableDatabase(c.a.a.a.a(-9700796706744L))).matches(c.a.a.a.a(-9748041347000L))) {
    c.a builder = new c.a(this.f2890b.getContext());
    View view = LayoutInflater.from(this.f2890b.getContext()).inflate(R.layout.custom_alert, (ViewGroup) null);
    ((TextView) view.findViewById(R.id.RES_2131296615)).setText(c.a.a.a.a(-9842530627512L));
    ((TextView) view.findViewById(R.id.alert_detail)).setText(c.a.a.a.a(-9885480300472L));
    builder.h(c.a.a.a.a(-9997149450168L), new DialogInterface$OnClickListenerC0066a());
    builder.f(c.a.a.a.a(-10031509188536L), new DialogInterface$OnClickListenerC0067b());
    builder.k(view);
    builder.l();
    return;
  }
  Toast.makeText(this.f2890b.getContext(), c.a.a.a.a(-10057278992312L), 0).show();
}
```

Let's take a look at `c.a.a.a.a()`. It is within the `c.a.a` package, so let's expand that:

![](https://i.ibb.co/84hYh3Z/4.png)

It contains 3 classes, and upon closer inspection we can see that the classes call functions from its sister classes. Let's take a look at our class of interest, `c.a.a.a`:
```java
package c.a.a;

public class a {
  public static final String[] f2669a;

  static {
    String[] strArr = new String[1];
    f2669a = strArr;
    strArr[0] = "{LONG UNICODE STRING}";
  }

  public static String a(long j) {
    return b.b(j, f2669a);
  }
}
```

I have redacted the string in the array as it is an extremely long string, and it looks like a messy block of jumbled-up characters, e.g. `衍ﾷﾖ렏궵澸ퟢ枱�...`. From this, we could tell it was likely Unicode. The function inside, `a(long)`, is the function that gets called, and it calls `b()` from the `b` class:
```java
public class b {
  public static String b(long id, String[] chunks) {
    long state = c.a(c.c(id & 4294967295L));
    long state2 = c.a(state);
    int index = (int) (((id >>> 32) ^ ((state >>> 32) & 65535)) ^ ((state2 >>> 16) & -65536));
    long state3 = a(index, chunks, state2);
    int length = (int) ((state3 >>> 32) & 65535);
    char[] chars = new char[length];
    for (int i = 0; i < length; i++) {
      state3 = a(index + i + 1, chunks, state3);
      chars[i] = (char) ((int) ((state3 >>> 32) & 65535));
    }
    return new String(chars);
  }

  public static long a(int charIndex, String[] chunks, long state) {
    return (((long) chunks[charIndex / 8191].charAt(charIndex % 8191)) << 32) ^ c.a(state);
  }
}
```

First we notice that it calls function `a()` from class `c`, but just by looking at this code, we can see that what `c.a.a.a.a()` does is just take in a long and retrieve a string from a string array. Now, we do the pro gamer move of reverse engineering: copy paste the decompiled functions into our own makeshift harness so we can read the contents. Of course, this isn't normally doable because disassembled C code is a jumbled mess, but in this case with the decompiled mapped Java Android code we can do this. Simply copy paste all 3 classes, create a Main.java that calls `c.a()` and we will be able to decipher all the weird calls. We can test it out with `a.a(-9516113113016L)` that we saw earlier in the `onClick()` function, inside one of the Toasts.
```java
public class Main {
  public static void main(String[] args) {
	System.out.println(a.a(-9516113113016L));
}
```
```
Do you think it will be that easy? Muahaha
```

Nice, we now have a working utility to help us solve the challenge.

Let's take a look back at the `onClick()` function:
```java
public void onClick(View v) {
  String password = a.this.f2886c.getText().toString();
  if (password.contains(c.a.a.a.a(-9421623832504L))) {
    Toast.makeText(this.f2890b.getContext(), c.a.a.a.a(-9516113113016L), 0).show();
  }
  if (this.f2891c.e(c.a.a.a.a(-9726566510520L), password, this.f2891c.getReadableDatabase(c.a.a.a.a(-9700796706744L))).matches(c.a.a.a.a(-9748041347000L))) {
    c.a builder = new c.a(this.f2890b.getContext());
    View view = LayoutInflater.from(this.f2890b.getContext()).inflate(R.layout.custom_alert, (ViewGroup) null);
    ((TextView) view.findViewById(R.id.RES_2131296615)).setText(c.a.a.a.a(-9842530627512L));
    ((TextView) view.findViewById(R.id.alert_detail)).setText(c.a.a.a.a(-9885480300472L));
    builder.h(c.a.a.a.a(-9997149450168L), new DialogInterface$OnClickListenerC0066a());
    builder.f(c.a.a.a.a(-10031509188536L), new DialogInterface$OnClickListenerC0067b());
    builder.k(view);
    builder.l();
    return;
  }
  Toast.makeText(this.f2890b.getContext(), c.a.a.a.a(-10057278992312L), 0).show();
}
```

We can now decipher all of the strings. Let's plug them all into the harness that we built earlier:
```java
public static void main(String[] args) {
  System.out.println(a.a(-9421623832504L));
  System.out.println(a.a(-9516113113016L));
  System.out.println(a.a(-9726566510520L));
  System.out.println(a.a(-9700796706744L));
  System.out.println(a.a(-9748041347000L));
  System.out.println(a.a(-9842530627512L));
  System.out.println(a.a(-9885480300472L));
}
```
```
My_P@s5w0Rd_iS-L34k3d
Do you think it will be that easy? Muahaha
user
12345
My_P@s5w0Rd_iS-L34k3d
Congrats!
govtech-csg{eZ_1nJ3CT10N}
```

Uhh, is that the flag right there? Well it is. If we look back at the `onCreate()` function, this is the alert that is created if you successfully carried out an SQL injection attack on the login. However, we can see here that we in fact do not even need to do SQL injection to solve the challenge. Of course, this method is a lot more complicated, but it is still a valid way of solving the challenge.

But wait, there's more!

# Patching The APK
Remember that there were 2 cheesy ways to solve the challenge? Patching the APK is actually one of them. Let's talk a little bit about smali.

Smali is a decompilation format for the dex format, which is used by dalvik, Android's Java VM implementation. The syntax is slightly confusing as it is basically pure pseudo-code, but what's great is that we can actually modify smali code and use APKTool to recompile it into an APK, then use another tool like Uber APK Signer to sign our APK so we can install the patched APK on our phone. Let's first use APKTool to decompile the APK:
```
$ apktool d mobile-challenge.apk
```

This will create a folder `mobile-challenge`, and inside it will be a folder `smali` which contains the smali code for all the different classes. At this point, I thought: "What if I patched the APK such that the condition check will either 1) always be true or 2) not even be there?" We are interested in the function `onCreate()`, within the class `f.a.a.a.a.e.a`, which is the class that contains the login logic. We know that the `onCreate()` function is actually a part of the class `b` inside `f.a.a.a.a.e.a`, so we open up the file `a$b.smali` inside the file path `smali > f > a > a > a > a > e`. Condition checks in smali is represented by code similar to:
```
sget-object v1, Lf/a/a/a/a/c/a;->a:Lf/a/a/a/a/c/a;

if-nez v1, :cond_0

...

:cond_0
```

With "..." representing truncated code and `:cond_0` encasing the action to carry out if the condition `cond_0` is met. `cond_0` is defined by the if comparison `if-nez v1`. Let's get back to looking for the condition check. We know that there are 2 condition checks within the function, so we need to make sure we get the correct one. We look for any "landmarks" that can help us pinpoint on the correct condition check to remove, and in this case only the second if statement will lead into a call into functions from `LayoutInflater`. Therefore, we find our condition check:
```
.local v3, "query":Ljava/lang/String;
const-wide v4, -0x8dda48aafb8L

invoke-static {v4, v5}, Lc/a/a/a;->a(J)Ljava/lang/String;

move-result-object v4

invoke-virtual {v3, v4}, Ljava/lang/String;->matches(Ljava/lang/String;)Z

move-result v4

if-eqz v4, :cond_1

...

move-result-object v4

invoke-static {v4}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

move-result-object v4

const v5, 0x7f0c0029

...

.line 106
.end local v2    # "builder":La/b/k/c$a;
.end local v4    # "view":Landroid/view/View;
.end local v5    # "title":Landroid/widget/TextView;
.end local v6    # "details":Landroid/widget/TextView;
goto :goto_0

.line 107
:cond_1
```

Where similarly, "..." denotes truncation of code irrelevant to discussion. We can see that within this conditional there is a call to a static function within `LayoutInflater`. Here we can see that after this specific condition `cond_1` is checked and is true, it will continue to the success code that we want to be able to hit. Let's remove the condition check as a whole. To remove the condition check, we just need to remove these parts:
```
.local v3, "query":Ljava/lang/String;
const-wide v4, -0x8dda48aafb8L

invoke-static {v4, v5}, Lc/a/a/a;->a(J)Ljava/lang/String;

move-result-object v4

invoke-virtual {v3, v4}, Ljava/lang/String;->matches(Ljava/lang/String;)Z

move-result v4

if-eqz v4, :cond_1
```
```
:cond_1
```

The latter `:cond_0` is the one at the very end of the earlier-shown smali code snippet. Leave all the code in the middle intact to make sure whatever is executed if condition check passes is still executed (if we remove it we literally remove the successful execution). Let's rebuild the patched APK and then sign it and install it on our device.

We can rebuild the APK with APKTool and sign it with Uber APK Signer, then use adb to install it on our device:
```
$ java -jar apktool_2.5.0.jar b mobile-challenge -o ./mobile-patched.apk 
$ java -jar uber-apk-signer-1.2.1.jar -a mobile-patched.apk
$ adb install mobile-patched-aligned-debugSigned.apk
```

We open up the patched app, go into the user login page, and simply just tap the "LOGIN" button.

![](https://i.ibb.co/M9X75YK/5.png)

Challenge solved, once again.

# Afterword
These were the 3 methods that I found could be used to solve this challenge. The method that I initially used to solve this challenge was with SQL injection, as it did seem to me to be the fastest way to solve it once I knew that this challenge was an SQL injection challenge. However, as I started attempting challenges within the post-login activity, I found it annoying to have to redo the SQL injection every time so I just ended up patching the APK so I wouldn't have to redo this challenge everytime I restart the app just to access the later challenges.

Of course, the second method seems almost too cheesy, but I felt it was interesting that the challenge could be solved even without knowledge of SQL injection, and especially since the JADX-decompiled code is not obfuscated it was as easy as copy pasting the helper function in order to directly access the "hidden" strings.

All in all, this was a pretty fun challenge, albeit a simple challenge, as I started finding more ways to solve it after initially solving it, and it's always fun when that happens. As mentioned, I believe that the fastest way is still to do SQL injection, and more experienced players might just attempt SQL injection straight away without even trying to decompile anything, and they would immediately get in (actually that was what I did). I obviously went back in to "properly" do the decompiling as it is always a learning experience for me, and even if I don't learn anything it still adds to my overall experience in debugging and reverse engineering Android apps.

I hope this writeup was relatively easy to understand for those without much CTF experience, I tried to go through each step and the thought process as precisely as possible. Even if you were unable to solve this challenge, fret not, as all things come with experience, just keep playing and eventually you'll get it :)

Thanks for reading.