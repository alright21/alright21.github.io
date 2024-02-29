---
title: "Intercepting Non-HTTP Traffic in Android"
date: 2023-09-06T12:25:03+02:00
draft: false
categories: sec
---

Recently I have started solving a mobile security CTF called [hpAndro](https://ctf.hpandro.raviramesh.info/) and I stumbled upon two challenges focusing on intercepting non-HTTP traffic in Android. I tried to check if I could do it by setting up Wireshark on my laptop and detect this communication directly from that, but it was not working. 

I thought I could change my perspective and monitor traffic directly from my device (it is always Linux). In this short article, I will show two methodologies I found to monitor app traffic, especially non-HTTP one.

## tcpdump

The first method uses tcpdump to monitor traffic directly from the device's command line. The steps to do so are quite simple. We can directly go to https://www.androidtcpdump.com/ and follow the instruction. IMPORTANT: we need to have a rooted device becase we have to run `tcpdump` as root!

After downloading the right binary (32bit or 64bit), we can push it into the device, and make it executable. Note that in this case I am not pushing it to a privileged folder because I am using a production build (physical device rooted), so I am not able to run `adb root`.

```bash
adb push tcpdump /data/local/tmp
adb shell
su
cd /data/local/tmp
chmod +x tcpdump
```

Aand it's done! Now we are able to run `tcpdump` from our shell (as root) and start intercepting traffic. We need to listen to an interface (`ip addr` to find out which interfaces are enbled on our Android device), and select which traffic to intercept. In this case, I had to dump TCP traffic on port 65000:

```bash
tcpdump -i wlan0 -A 'tcp port 65000'
```

## PCAPdroid

The first method requires us to have a rooted device, which is not always easy. Luckily we have another solution, which is also fast to set up and does not require root privileges: entering PCAPdroid. This mobile application can be downloaded from the [Google Play store](https://play.google.com/store/apps/details?id=com.emanuelef.remote_capture&hl=en&gl=US). It is actually a game changer because it allows us to see all the traffic coming from and to our mobile device. It creates a local VPN to redirect everything, so it is not necessary to mess up with routing tables (which requires high privileges). We just need to start capturing and in the "Connections" tab we will see all the connections created.

<figure>
  <img src="/assets/pcapdroid_overview.png" alt="PCAPdroid overview" style="width:60%">
  <figcaption>PCAPdroid overview</figcaption>
</figure>

<figure>
  <img src="/assets/pcapdroid_tcp.png" alt="PCAPdroid TCP" style="width:60%">
  <figcaption>PCAPdroid intercept TCP traffic</figcaption>
</figure>

The project is also open source: https://github.com/emanuele-f/PCAPdroid! All credits goes to [emanuele-f](https://github.com/emanuele-f).

And that's all for this brief post, see you next time!