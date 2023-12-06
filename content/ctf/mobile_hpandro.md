---
title: "hpAndro Mobile CTF"
date: 2023-12-07T08:00:00+02:00
draft: false
categories: ctf
---

# hpAndro Mobile CTF

Hello everyone! In this blog post, I will explain how I solved some challenges in [hpAndro](https://ctf.hpandro.raviramesh.info/) mobile CTF. I am trying to learn mobile security, and this mobile app helped me to improve my skills, especially on what concern dynamic analysis. I will update this article in the future, so keep an eye on that! Furthermore, I suggest you to try these challenges first on your own, but do not hesitate to look for the solutions if you need it:) And if you have a better solution, feel free to contact me and I will be happy to learn from you!

We can download the application from [github](https://github.com/RavikumarRamesh/hpAndro1337/blob/main/Android%20AppSec%20(Kotlin)/1.3/com.hpandro.androidsecurity_1.3.apk), and install it in our device using `adb install com.hpandro.androidsecurity_1.3.apk`, after connecting our phone via USB(or turning on our emulator). The challenges are divided into different sections, and below I will try to tackle them without following a specific order.

## HTTP Traffic
### HTTP Traffic
We need to set up a proxy to intercept mobile traffic and see what the application sends and receive. We can use Burp Suite. If you need some help with that, I wrote a [post](/blog/mobile_security) about this.

After setting up our proxy, we can start seeing the traffic, and we can easily retrieve the first flag, contained in the response header. In this scenario, we do not need to set up any certificate because the traffic is not encrypted.

<figure>
  <img src="/assets/hpandro_http.png" alt="hpAndro HTTP traffic" style="width:100%">
  <figcaption>HTTP traffic flag</figcaption>
</figure>

### HTTPS Traffic
After installing Burp certificate, we can intercept also HTTPS traffic, when not SSL pinning is implemented. In this challenge, we do not need anything complex, and the basic mobile setup is more than enough to complete it.

<figure>
  <img src="/assets/hpandro_https.png" alt="hpAndro HTTPS traffic" style="width:100%">
  <figcaption>HTTPS traffic flag</figcaption>
</figure>

## Non-HTTP Traffic
Those challenges made me research about intercepting non HTTP-traffic from our mobile device and I found out two solutions. If you are interested in more details, have a look at my [article](/blog/mobile_nottp) about it. I will show you the solution using [PCAPdroid](https://github.com/emanuele-f/PCAPdroid).

### TCP Traffic
To solve this challenge, I had a look at the activity in order to get the TCP `IP` and `PORT`: they are both inside `hpandro.android.security.utils.AppConstant`.

<figure>
  <img src="/assets/hpandro_tcp.png" alt="hpAndro TCP details" style="width:100%">
  <figcaption>TCP details inside the Activity</figcaption>
</figure>

Based on this information, we can use PCAPdroid to monitor the traffic and retrieve the flag directly from the app, as shown below.

<figure>
  <img src="/assets/hpandro_tcp1.png" alt="hpAndro TCP communication" style="width:60%">
  <figcaption>TCP communication</figcaption>
</figure>

### UDP Traffic

The same process we used for TCP traffic can be used for UDP. We retrieve the `IP` and `PORT` from the activity and we monitor the traffic with PCAPdroid.

<figure>
  <img src="/assets/hpandro_udp.png" alt="hpAndro UDP details" style="width:100%">
  <figcaption>UDP details</figcaption>
</figure>

<figure>
  <img src="/assets/hpandro_udp1.png" alt="hpAndro UDP communication" style="width:60%">
  <figcaption>UDP communication</figcaption>
</figure>


## Logs
This section is quite easy and we can solve it using `adb logcat`. When I debug an application, I usually use the following command, using `frida-ps` to get the process ID, and `head -n 1` it happened to find application running multiple processes with the same package name (I don't know the theory behind that, maybe I will explore it in the future):
```bash
adb logcat -v color | grep $(frida-ps -Uai | grep -i "hpandro.android.security" | awk '{print $1}' | head -n 1)
```

### Informational Logs
### WTF Logs 
### Verbose Logs
### Debug Logs
### Warnings Logs
### Error Logs
By looking at the code in `jd-gui`, we can see that the `LogsTaskActivity` handles a JSON response based on a `String type`, which is set when the request is made. We can also see this request directly in Burp, and we will see that the app adds GET parameter `flag=` to specify the type of encrypted flag. 

<figure>
  <img src="/assets/hpandro_logs.png" alt="hpAndro logs" style="width:100%">
  <figcaption>Based on the <code>String type</code>, the application uses a different log level</figcaption>
</figure>

<figure>
  <img src="/assets/hpandro_logs1.png" alt="hpAndro logs1" style="width:100%">
  <figcaption>The application retrieves the encrypted flag using <code>flag=</code> GET parameter to switch between log level</figcaption>
</figure>

By opening the logcat, we will be able to see all the flags printed out. I created a simple `frida` script to make the request one after the other, so all the flags will be printed subsequentially. We hook method `getLogsData` because it is the one where the flow starts, and it is possible to customize the type of log to retrieve (`debug`,`error`, ...). As a result, we do not need to open each activity, but we can retrieve every flag by open one of the logs' activity. We can launch the script with `frida -U -f hpandro.android.security -l logs.js`, navigate to a logs activity and click the `CHECK LOG` button to trigger the hook.

```javascript
Java.perform(()=>{

    let FlagBaseActivity = Java.use("hpandro.android.security.utils.operation.FlagBaseActivity");
    FlagBaseActivity["getLogsData"].implementation = function (presenter, type) {
        console.log(`FlagBaseActivity.getLogsData is called: presenter=${presenter}, type=${type}`);

        this["getLogsData"](presenter,"d");
        this["getLogsData"](presenter,"i");
        this["getLogsData"](presenter,"v");
        this["getLogsData"](presenter,"e");
        this["getLogsData"](presenter,"wtf");
        this["getLogsData"](presenter,"w");
    };

    
});
```

<figure>
  <img src="/assets/hpandro_logs2.png" alt="hpAndro logs2" style="width:100%">
  <figcaption>Logcat result</figcaption>
</figure>

## Symmetric Encryption
In this section we need to use a lot of `frida` to hook different functions to decrypt the flags the application receives from the backend. We have access to the code, so we can have a look at all the activities, find interesting methods and use them accordingly, without looking for specific key or secrets. That's the power of `frida`! I will not go into the details on how the algorithm works: feel free to have a look at the challenge details to have a better insight:)
### DES
This level is coded inside `DESTaskActivity`. The method we are interested in is `decrypt(String value)`. We can hook it with Frida, and it should return us the decrypted flag. This method is called in `onGetLogs()`, which is called automatically when the app receives a response from the backend: we do not need to call it manually, but we have to trigger it by clicking on the challenge button.

```javascript
Java.perform(()=>{
  let DESTaskActivity = Java.use("hpandro.android.security.ui.activity.task.encryption.DESTaskActivity");
    DESTaskActivity["decrypt"].implementation = function (value) {
        console.log(`DESTaskActivity.decrypt is called: value=${value}`);
        let result = this["decrypt"](value);
        console.log(`DESTaskActivity.decrypt result=${result}`);
        return result;
    };
});
```
<figure>
  <img src="/assets/hpandro_des.png" alt="hpAndro des" style="width:100%">
  <figcaption>DES decryption</figcaption>
</figure>



### 3DES
This level is coded inside `ThreeDESActivity`. As for DES, we can hook method `decrypt(String str, String str2)`, which is called inside `onGetLogs()` and retrieve the flag.
```javascript
Java.perform(()=>{
  let ThreeDESActivity = Java.use("hpandro.android.security.ui.activity.task.encryption.ThreeDESActivity");
    ThreeDESActivity["decrypt"].implementation = function (str, str2) {
        console.log(`ThreeDESActivity.decrypt is called: str=${str}, str2=${str2}`);
        let result = this["decrypt"](str, str2);
        console.log(`ThreeDESActivity.decrypt result=${result}`);
        return result;
    };
});
```

<figure>
  <img src="/assets/hpandro_3des.png" alt="hpAndro 3des" style="width:100%">
  <figcaption>3DES decryption</figcaption>
</figure>

### RC4
This level is coded inside `RC4Activity`. As for the previous ones, we hook `decrypt(String str)`, and the flag will be the return value. In this case, the application returns a `byte` array: we can convert its values with `String.fromCharCode()`, but we also need to keep in mind that Java can use negative integers, so we transform the value accordingly (see [this](https://reverseengineering.stackexchange.com/questions/17835/print-b-byte-array-in-frida-js-script/22255#22255) article for more details).

```javascript
Java.perform(()=>{
  let RC4Activity = Java.use("hpandro.android.security.ui.activity.task.encryption.RC4Activity");
    RC4Activity["decrypt"].implementation = function (str) {
        console.log(`RC4Activity.decrypt is called: str=${str}`);
        let result = this["decrypt"](str);
        console.log(`RC4Activity.decrypt result=${result}`);
        // We transform any negative value using bitwise AND
        var buffer = Java.array('byte', result);
        let resultString = "";
        for(var i = 0; i < buffer.length; ++i){
            resultString += (String.fromCharCode(buffer[i] & 0xff));
        }
        console.log(`RC4Activity.decrypt toString result=${resultString}`);
        return result;
    };
});
```

<figure>
  <img src="/assets/hpandro_rc4.png" alt="hpAndro rc4" style="width:100%">
  <figcaption>RC4 decryption</figcaption>
</figure>

### Blowfish
This level is coded inside `BlowfishActivity`. As the previous ones, we hook `decrypt(String str)`, and the flag will be the return value.
```javascript
Java.perform(()=>{
  let BlowfishActivity = Java.use("hpandro.android.security.ui.activity.task.encryption.BlowfishActivity");
    BlowfishActivity["decrypt"].implementation = function (str) {
        console.log(`BlowfishActivity.decrypt is called: str=${str}`);
        let result = this["decrypt"](str);
        console.log(`BlowfishActivity.decrypt result=${result}`);
        return result;
    };
});
```

<figure>
  <img src="/assets/hpandro_blowfish.png" alt="hpAndro blowfish" style="width:100%">
  <figcaption>Blowfish decryption</figcaption>
</figure>

### AES
This level is coded inside `AESActivity`. By hooking any of the decrypt methods, it does not seem to have any execution. In fact, the method is never called, but we can use `frida` to directly call it! I spent some time to figure out the proper way to call the method, and what we need to hook, I suggest reading carefully the code and figure out what is needed in order to correctly solve the challenge (it was a fun one!).

We can investigate the class and see that there are three different decrypt methods, and the first one called is `decryptStrAndFromBase64(String str, String str2, String deStr)` but, unfortunately, this method is never called (at least in version 1.3, the one I am working with). This method asks for two strings which I assume they are the initialization vector and the secret key (see [Wikipedia](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) for more details about AES encryption). We can find these keys inside the `res/values/strings.xml`.

<figure>
  <img src="/assets/hpandro_aes.png" alt="hpAndro aes" style="width:100%">
  <figcaption>AES initialization vector and secret key</figcaption>
</figure>

There is an interesting catch: the first `decrypt(String ivStr, String keyStr, byte[] bArr)` is called with `str2` in both `ivStr` and `keyStr` parameters. So we need to use the secret both for initialization vector and key! Moreover, the encrypted flag has to be decoded from Base64 before calling this method.

<figure>
  <img src="/assets/hpandro_aes1.png" alt="hpAndro aes1" style="width:100%">
  <figcaption>Decrypt function called with IV==KEY</figcaption>
</figure>

So, how can we do it? We can retrieve the encrypted flag by intercepting the request using Burp and use its value inside the code, get it by parsing the response get from `onGetLogs(JsonObject response)`. After that, we need to call the `decryptStrAndFromBase64` method. There is another problem: these methods must be called with an instance of the activity. The solution consists in calling the method directly inside the hook created for `onGetLogs`. The following `frida` script is executed when we click the button to retrieve the flag.

```javascript

Java.perform(()=>{
  let AESActivity = Java.use("hpandro.android.security.ui.activity.task.encryption.AESActivity");
    AESActivity["decryptStrAndFromBase64"].implementation = function (str, str2, deStr) {
        console.log(`AESActivity.decryptStrAndFromBase64 is called: str=${str}, str2=${str2}, deStr=${deStr}`);
        let result = this["decryptStrAndFromBase64"](str, str2, deStr);
        console.log(`AESActivity.decryptStrAndFromBase64 result=${result}`);
        return result;
    };

    AESActivity["onGetLogs"].implementation = function (response) {
        console.log(`AESActivity.onGetLogs is called: response=${response}`);
        this["onGetLogs"](response);

        // Parse the JSON response
        let encryptedFlag = JSON.parse(response)["flag"];
        // Call the method using the instance
        this["decryptStrAndFromBase64"]('hpAndro','hpAndro', encryptedFlag);
    };
});
```

<figure>
  <img src="/assets/hpandro_aes2.png" alt="hpAndro aes2" style="width:100%">
  <figcaption>AES decryption</figcaption>
</figure>

### Predictable Initialization Vector
This level is coded inside `PredictableInitializationVectorActivity`. It is an interesting level because we have to find a value that we do not have by brute forcing it. The most simple way is to code it directly using `frida`, call the method to decrypt the flag and verify that the decryption succeeds (we know that every flag starts with `hpandro{`). The decryption method is `decryptStrAndFromBase64(String str, String str2, String deStr)`, and we can call it directly from the `onGetLogs` hook. We know that the initialization vector is a four-digit code (`XXXX`) converted to a string, so we can loop over all the values, and we will be able to find the correct flag.

```javascript
Java.perform(()=>{
  let PredictableInitializationVectorActivity = Java.use("hpandro.android.security.ui.activity.task.encryption.PredictableInitializationVectorActivity");
    PredictableInitializationVectorActivity["onGetLogs"].implementation = function (response) {
        console.log(`PredictableInitializationVectorActivity.onGetLogs is called: response=${response}`);
        this["onGetLogs"](response);

        let encryptedFlag = JSON.parse(response)["flag"];

        console.log("Start Bruteforce...")
        for (let i = 0; i <= 9999; i++) {
            // Pad each value with leading zeros
            const iv = i.toString().padStart(4, '0');
            let decryptedFlag = this["decryptStrAndFromBase64"](iv,"hpAndro",encryptedFlag);
            if(decryptedFlag.startsWith('hpandro')){
                console.log(`Match found! IV=${iv}, decryptedFlag=${decryptedFlag}`);
            }
          }

    };
});
```

<figure>
  <img src="/assets/hpandro_predictableiv.png" alt="hpAndro predictableiv" style="width:100%">
  <figcaption>Predictable initialization vector found</figcaption>
</figure>

## Asymmetric Encryption
After symmetric encryption, there is also an asymmetric encryption challenge. We can solve it using the same technique.

### AES

This challenge is coded inside `RSAActivity`. We can find the `decrypt(PrivateKey privateKey, byte[] bArr)` method, which is called inside `onGetLogs`. We just need to hook it and print the return value to get the flag. The method receive as input the private key required for the decryption (the flag is encrypted with a public key, and you need the private one to decrypt it). In this case the result is a byte array, so we need to convert it to a `String`.

```javascript
Java.perform(()=>{

  let RSAActivity = Java.use("hpandro.android.security.ui.activity.task.encryption.RSAActivity");
    RSAActivity["decrypt"].implementation = function (privateKey, bArr) {
        console.log(`RSAActivity.decrypt is called: privateKey=${privateKey}, bArr=${bArr}`);
        let result = this["decrypt"](privateKey, bArr);

        var buffer = Java.array('byte', result);
        let resultString = "";
        for(var i = 0; i < buffer.length; ++i){
            resultString += (String.fromCharCode(buffer[i] & 0xff));
        }
        console.log(`RSAActivity.decrypt result=${resultString}`);
        return result;
    };
})
```

<figure>
  <img src="/assets/hpandro_rsa.png" alt="hpAndro rsa" style="width:100%">
  <figcaption>RSA decryption</figcaption>
</figure>


## Hashing

Hashing is used to store sensitive data, like login credentials, in databases or other data storage, so that attackers who gain control over this data, cannot recover the information. In fact, hashing algorithms are one way algorithms: it is not possible to retrieve the information after it has been hashed. In this section we will see vulnerable implementations of those algorithms.

### MD4

MD4 is the first hashing challenge. It is an algorithm suffers from collision attacks. When there is a weak hashing algorithm in a challenge, an online tool could be the solution. I found out that https://md5hashing.net/hash is what we need. But we need to recover the hashes first. We can retrieve the database by going into the data folder of the app, located at `/data/data/hpandro.android.security/`. Here we can see a folder named `databases`, where the `AndroidSecurity.db` file is stored. I used [DBBrowser for SQlite](https://sqlitebrowser.org/) to navigate the database and get all the hashes. We can then use the tool above to retrieve all the original pieces, and we will have the solution.

### MD5

We can use the same methodology used for MD4, to find common MD5 hashes and rebuild the flag.

### SHA1

Same as the previous hashing challenges.

## Root Detection

### Root Management Apps

