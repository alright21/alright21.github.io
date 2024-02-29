---
title: "Reversing and Hooking Native Libraries in Android with Frida"
date: 2023-10-26T18:01:16+02:00
draft: false
categories: sec
---

Android applications are written in Java (Kotlin): we can use tools like jadx to decompile Java smali code to analyze the code, identify interesting methods and find possible secrets.

In some cases, Android applications use native libraries to perform some specific tasks: they may be used for root detection, or they can also be responsible for encryption, or simply to run simple tasks, like hide secrets. We can find libraries used inside the apk, by unpacking the `.apk` using `apktool d`, inside the `/lib` folder. Native means that each library is compiled based on the hardware architecture the application will run on, meaning that we will have different folders with the same libraries, but compiled for different architectures.

How does our application interact with native libraries? If we look inside our decompiled Java code, we can see that our `.so` file is loaded using `System.loadLibrary()` function and each method we want to use that is defined inside the native code has the `native` modifier. Android allows us to write some methods in C and directly call them inside our Java code. How is this magic even possible? Entering JNI, or Java Native Interface [1], an interface framework that defines a way to use C/C++ code in Java.


We will use as an example the vulnerable application hpAndro [2], and we will solve the challenge "Binary Protection -> Native Function Call".

We can see that inside the Activity `NativeFunTaskActivity`, the library `nativefuncall.so` is loaded inside the `init()` method and then `hello()` method is called when we press the button.

<figure>
  <img src="/assets/mobile_security_native_init_method.png" alt="init method" style="width:100%" >
  <figcaption>Init method sets up a <code>onClickListener</code> that calls native <code>hello()</code></figcaption>
</figure>

The goal of the challenge is to call the native method `flag()`, which is defined inside Activity, but never called. We can use frida to call this method directly, but we need to keep in mind an important thing: we have to call the method after the native library is being called! Where should we do it? We can hook `init()` method, call it and then call our desired method. An example solution could be:

```javascript
Java.perform(()=>{

    let NativeFunTaskActivity = 
    Java.use("hpandro.android.security.ui.activity.task.binary.NativeFunTaskActivity");

    // We hook flag method and we print the result before returning
    NativeFunTaskActivity["flag"].implementation = function () {
        console.log(`NativeFunTaskActivity.flag is called`);
        let result = this["flag"]();
        console.log(`NativeFunTaskActivity.flag result=${result}`);
        return result;
    };

    // We hook init, we call the original method to load the native library, 
    //and then we can call flag()
    NativeFunTaskActivity["init"].implementation = function () {
        console.log(`NativeFunTaskActivity.init is called`);
        this["init"]();

        this["flag"]();
    };

});

```

## Analyze Native Code

That's great! But... hang on a moment: how can we see the code of `flag()`? We can use Ghidra [3] to disassemble our `nativefuncall.so`! After opening our library, we are able to see all the native methods listed inside the "Functions" folder on the left

<figure>
  <img src="/assets/mobile_security_native_methods.png" alt="native methods" style="width:100%" >
  <figcaption>Native methods</figcaption>
</figure>

We can see that the name of those methods is quite long and does not seem to match our Java methods but, if we look closely, we can see that every method starts with `Java_`, it is followed by the `complete_package_name_structure_`, and it ends with `methodName`. This is how we need to call native methods when working with JNI.

If we take a look at the decompiled code, we can see that the `hello()` method returns a Java string, which is hard coded, while the `flag()` methods does some fancy append to build the string and returns it. In this case, the code seems quite clear, but Ghidra is not able to properly parse JNI symbols [4]. For example, the first argument of every native method must have a pointer to the JNI environment, but Ghidra seems to interpret it as a `long*`. Luckily, we can import JNI symbols mapping into Ghidra by downloading JNIAnalyzer jdt package [5] (it is also possible to use the plugin directly, but I still have to learn about it). 

<figure>
  <img src="/assets/mobile_security_native_jni.png" alt="jnisymbols" style="width:100%" >
  <figcaption>How to import JNI symobls</figcaption>
</figure>

After importing the symbols, we can retype our first argument from `long*` to `JNIEnv*`.

<figure>
  <img src="/assets/mobile_security_native_flag_method.png" alt="flag method" style="width:100%" >
  <figcaption>Flag method after variable retyping</figcaption>
</figure>

## Hooking Native Methods

We can also hook native methods directly, read the arguments, or modify the return value. Frida will help us with that. We will use `Interceptor.attach` method to attach to our native function, and then we can use `onEnter` and `onLeave` callbacks to interact with native code execution.

```javascript

Interceptor.attach(Module.getExportByName('libnativefuncall.so', 
'Java_hpandro_android_security_ui_activity_task_binary_NativeFunTaskActivity_flag'), {
    onEnter: function(args) {
        console.log("flag() onEnter: speaking from native")
    },
    onLeave: function(retval) {
        // retval is a native pointer to the result, we need to cast it to java string
        var resultString = Java.cast(retval, Java.use('java.lang.String'))
        console.log("flag() onLeave: " + resultString.toString());
    }
});
```

This code is not sufficient to solve the challenge, since we need to call the `flag()` method in order to trigger this hook, and we will see an error when loading this script because the library is not being loaded until `init()` is called. If we merge our scripts, we will see our flag print on the console log, and also when the native method is called.

<figure>
  <img src="/assets/mobile_security_native_console.png" alt="native console" style="width:100%" >
  <figcaption>We see the flag printed on the logs</figcaption>
</figure>

## Conclusion

Working with native code is an interesting way to learn something new about reverse engineering. I am still learning, so I may have made some mistakes. If you have some feedback, please contact me and I will be eager to learn from you:)

## References
- [1] https://en.wikipedia.org/wiki/Java_Native_Interface 
- [2] https://ctf.hpandro.raviramesh.info/
- [3] https://ghidra-sre.org/
- [4] https://docs.oracle.com/javase/7/docs/technotes/guides/jni/spec/functions.html
- [5] https://github.com/Ayrx/JNIAnalyzer/blob/master/JNIAnalyzer/data/jni_all.gdt
