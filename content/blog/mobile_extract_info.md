---
title: "Extract App Information from APK and IPA Package"
date: 2024-01-07T10:15:31+01:00
draft: false
categories: blog
---

# Extract App Information from APK and IPA Package

During my mobile security journey, I often get stuck when searching for the publicly known app information that I am testing. We are talking about app name, app main package, version number and build. This information is important for reporting: I usually fire up my MobsF Docker instance and get this information from there. This process is often too slow, especially for big applications: I often forget to note down this data before turning off the Docker instance:(

This mini guide serves as a reminder for me and, hopefully, a precious tip for you. I will explain an easier way to extract that information via Linux command line and a bit of Python!

## Android (APK)
Android applications contains this information in a file called `AndroidManifest.xml`[[1]](https://developer.android.com/guide/topics/manifest/manifest-intro). This file contains details about the application structure, the entry point (MainActivity), the activities, what hardware and software the app will use, service provider and broadcast receiver, ...

We can extract all the information we need by installing `apkinfo` from the `pyaxmlparser`[[2]](https://github.com/appknox/pyaxmlparser) python package (`pip3 install pyaxmlparser`) and run
```bash
apkinfo app.apk
```

It will give an output like this one:

```bash
APK: proxydroid.apk
App name: ProxyDroid
Package: org.proxydroid
Version name: 3.2.0
Version code: 72
Is it Signed: True
Is it Signed with v1 Signatures: True
Is it Signed with v2 Signatures: True
Is it Signed with v3 Signatures: False
```

Before that tool, I was using the technique described below, which requires a bit more parsing (I will probably remove this part for conciseness).


We can use `aapt` to `dumb` the `badging` information, and extract the package information using Linux string manipulation magic tool `sed`:

```bash
aapt dump badging app.apk | grep package | sed -e "s/package: //" -e "s/'//g" -e "s/ /\\n/g"
```

This will give an output like the one below:

```bash
name=com.example.com
versionCode=1
versionName=1.0
compileSdkVersion=33
compileSdkVersionCodename=13
```



## iOS (IPA)

We can say that the equivalent for AndroidManifest in IPA package is `Info.plist`[[3]](https://developer.apple.com/documentation/bundleresources/information_property_list).

While I was writing this article, I found out that [LaurieWired](https://www.youtube.com/@lauriewired) published the perfect [video](https://www.youtube.com/watch?v=KL899jMSD8w) about this topic. She suggests using plistlib[[4]](https://docs.python.org/3/library/plistlib.html) Python library, which is perfect for parsing binary and xml .plist files.

Here is my python script to extract the information I usually add in my reports.

```python
import plistlib
import sys


def parse_plist(plist_file_name):

    with open(plist_file_name,'rb') as fp:
        plist = plistlib.load(fp)

        print('App name: ' + plist['CFBundleDisplayName'])
        print('Package: ' + plist['CFBundleIdentifier'])
        print('Version code: '  + plist['CFBundleShortVersionString'])
        print('Version bundle: ' + plist['CFBundleVersion'])
        print('Version platform: ' + plist['DTPlatformVersion'])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_plist.py <Info.plist>")
        sys.exit(1)

    plist_file_name = sys.argv[1]

    parse_plist(plist_file_name)
```


(I will probably remove this part for conciseness)
My previous technique was a bit more complex and not perfect, but it was getting the job done. I used [`plistutil`](https://manpages.debian.org/testing/libplist-utils/plistutil.1.en.html) to convert Info.plist into a readable format (sometimes this file is stored in XML, sometimes in binary, we want the XML version and this tool helps us with that), and manually extract the tags (gosh the code is quite messy).

```python
import sys
import xml.etree.ElementTree as ET


def parse_xml_from_file(file_path):
    # Parse the XML file
    tree = ET.parse(file_path)
    # we need to add [0] or it will get <plist> empty tag
    root = tree.getroot()[0]

    # Save all the top level string tags in a dictionary
    plist = {}
    i=0
    while i < len(root):
        if root[i].tag == 'key':
            if root[i+1].tag == 'string':
                plist[root[i].text] = root[i+1].text
            i+=2


    print('CFBundleDisplayName = ' + plist['CFBundleDisplayName'])
    print('CFBundleIdentifier = ',plist['CFBundleIdentifier'])
    print('CFBundleShortVersionString = ' + plist['CFBundleShortVersionString'])
    print('CFBundleVersion = ' + plist['CFBundleVersion'])
    print('DTPlatformVersion = ' + plist['DTPlatformVersion'])
            

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Usage: python file.py <xml_file>")
        sys.exit(1)

    xml_file_path = sys.argv[1]

    parse_xml_from_file(xml_file_path)
```


## Conclusion

That's all for today! I hope you found something useful. Feel free to get in touch with me if you have any more questions:)

## References

- [1] **Android Manifest Introduction** - https://developer.android.com/guide/topics/manifest/manifest-intro
- [2] **pyaxmlparser** - https://github.com/appknox/pyaxmlparser
- [3] **Info.plist documentation** - https://developer.apple.com/documentation/bundleresources/information_property_list
- [4] **plistlib** - https://docs.python.org/3/library/plistlib.html