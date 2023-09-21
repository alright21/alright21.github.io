---
title: "Mobile Security Introduction"
date: 2023-07-23T18:00:00+02:00
draft: false
categories: blog
---

# Mobile Security Introduction
After quite a while, I finally decided to upload this article, and now I have found the courage to do so. If you come across any inconsistencies, I am always open to feedback. I will continuously update it, aiming to create a comprehensive 'mobile security introduction garden.' Have fun reading! :)
## Setup

Every mobile assessment requires some different setup compared to web applications. In this guide, we will explain how to enter the beatiful world of mobile security, and not feel overwhelmed by do so.

## Standard setup

We need to set up our environment to proxy the requests coming from the mobile phone. Unfortunately, almost every application implements ssl pinning techniques to prevent this: the application uses some methods to check the server certificate against a whitelist, and allows communication only if the other end is trusted. We must bypass this check to be able to intercept the request using our beloved Burp Suite.

### Installing Burp certificates

Firstly, we need to install burp certificates on our devices. We can download them from the Burp Suite -> Proxy -> Proxy settings tab and copy them inside the device, but there is a (for me) faster way to do it (that works both in Android and iOS):
- **Android**: `Settings -> Wifi -> select our network (the one where also the PC is connected to) -> Settings gear -> Edit Connection (the last two steps may slightly differ on your configuration, Google is your friend) -> choose Manual Proxy -> PC IP address and Burp suite listening port (I usually set up a different port, like 8086, so I can easily filter my requests) -> Save`. Now we can connect to http://burp and download the certificate. We must rename its extension from .der to .cer, or we won't be able to install it. We can now install it: `Settings -> Security -> Credentials ->  Install a certificate`
- **iOS**: `Settings -> Wifi -> Info button on our network -> HTTP Proxy -> Manual -> PC IP address and Burp suite listening port -> Save`. Download the certificate and the system will suggest going to Settings again to install it (check Setting notifications, it should be there).

Now, we should be able to intercept HTTPS traffic if the applications do not implement SSL Pinning techniques. If the applications implement those checks, we can use some standard Frida scripts: these scripts are usually found online, for most of the standard techniques. If the developers implement some custom checks, we need to reverse the code and find which methods are used. Writing Frida scripts is beyond the scope of this guide (check the mobile guide for some details).


### Installing applications

Applications are usually shared as compressed packages that we can install using `adb` (Android) or `ideviceinstaller` (iOS). Sometimes, we need to install them from the official store (remember to disable HTTP Proxy), or test stores (Testflight application for iOS).
- **Android**: `adb install <app.apk>`
- **iOS**: `ideviceinstaller -i <app.ipa>`



### Frida setup
We usually need to use Frida for different purposes: bypass SSL pinning and root checks, and hook encryption functions, to name a few. iOS devices needs a different setup that we will try to explain in future updates of this article.

For Android devices, we need to set up our server manually: it is not difficult, and it is a gentle introduction to `adb`. The necessary steps are:
1. download the latest Frida release from https://github.com/frida/frida/releases. The latest version should be fine, but some phones do complain about it. Try older versions, if necessary
2. extract the executable with `unxz frida-server.xz`
3. copy the executable inside the device (Android smartphone must have USB debugging active and adb running): `adb push frida-server/data/local/tmp`
4. if the device allows it, try to restart `adb` in root mode (`adb root`). If it is not possible, connect to the shell (`adb shell`) and elevate the privileges with `su`
5. set correct file permissions: `chmod 755 /data/local/tmp/frida-server`
6. start the server: `/data/local/tmp/frida-server &`
7. now the server is running, you can go back to your host device and start hacking with frida scripts:)

We are ready to use frida on our devices! Remember that, if the device is turned off, we need to start the server again (steps 4. and  6.).

We can start our frida journey by analyzing some useful commands that we need to spawn (launch the application) or attach (the application is already running) to a mobile application:
- `frida-ps -Uai`: list installed application names and packages
- `frida -U -F -l <script.js>`: attach to the foreground application
- `frida -U -f <package_name> -l <script.js>`: spawn desired application by package name
- `frida -U <app name>(or <PID>) -l <script.js>`: attach to application name

### Objection setup
Another interesting tool is `objection`, a frida wrapper written in python that automates some boring tasks. It is not perfect and it is not being updated regularly, but it is sometimes useful for some basic tests. You can install it using `pip`. Here is a list of useful commands:
- `objection -g <package name> explore`: spawn desired application by package name
- `objection -g <pid> explore`: attach to the desired application by pid
- `objection -g <app name> explore`: attach to the desired application by app name

Another interesting feature that objection offers is the ability to watch a Java Class or a Java Class Method, by knowing the full package. We can retrieve the full package path by navigating the decompiled source in jadx (see Static Analysis section). After retrieving the package, we can monitor a specific class when a new instance is created, or when a method is called, what arguments are passed and what is the return value. After spawning the process (or attaching to it), an interactive console allows us to input these commands (objection offers an autocomplete feature that helps us explore all the commands).
- `android hooking watch class <package path>.<class name>`: watch the full class and its methods.
- `android hooking watch class_method <package path>.<class name>.<method> --dump-args --dump-return --dump-backtrace`: watch a specific method, logging when it is called
  - `--dump-args`: print the argument passed to a specific method
  - `--dump-return`: print the return value (based on the toString method implementation)
  - `--dump-backtrace`: print the complete stack trace that caused the specific method to be called

If we have to hook a specific class or class_method right after the application is spawned, we can use `-s` flag after `explore` and issue the objection command we want to execute.

## Static Analysis

Frida and Objection helps us instrumenting the applications and dinamically modify their flow, tamper with the arguments and return values, and watch the execution. Unfortunately, we cannot do much without knowing a bit about how the application is built, what are the activities, services, and libraries used. In mobile application assessment, the analysis of web requests is a small part of the job: we need to improve our reversing and static analysis skill to be able to understand how the client side works, if the application stores sensistive data inside the code, use unsafe methods, etc.

This section is mainly focused on Android because it is easier to obtained readable decompiled code with Java or Kotlin, rather than iOS application. For iOS application, the best solution is to use Ghidra (or IDA, if you have access to a paid licence). We just need to unzip our .ipa package, find the binary file (which is called as the app), and import it. We can use this method to search for interesting strings inside.

For Android application, we can use [jadx](https://github.com/skylot/jadx) to decompile the Java classes and resources. Jadx offers a command line tool, but I personally think that jadx-gui is easier to grasp as a beginner because it offers a great search tool, and some other interesting features that we will see in this guide. 

On Linux, we can download the zip file, go to the `bin` directory, and run `jadx-gui`. We can then open an .apk file: the program will start to decompile it, and the result will be shown as a file tree in the left side of the window. Here, we can start navigating the different activities and classes, find the package paths, understand what external libraries are used, etc.

We can now open a file containing Java code and use some powerful keybindings. Go to a method declaration and click:
- `x`: go to usage. Search where the method is used.
- `f`: copy as Frida snippet. Copy a Frida hook that can be used to start scripting the easily. It automatically finds the full class name, overloads the method, prints the arguments and return value.
