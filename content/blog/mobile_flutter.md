---
title: "Intercepting Traffic in Mobile Flutter Applications"
date: 2023-08-01T08:50:38+02:00
draft: false
---

# Intercepting Traffic in Mobile Flutter Applications

During our tests, it may happen that we have to find vulnerabilities in applications built with the Flutter framework. It is pretty common when we have both Android and iOS apps. This framework raises some problems when we need to intercept traffic for two reasons:
1. flutter apps are proxy unaware - if we add a proxy listener from the settings of our phone, the application will ignore it
2. flutter apps often implement ssl pinning techniques that are not easily bypassed using standard frida scripts

Below are explained the solutions for Android and iOS. For iOS, I will explain the procedure
that the researchers from [nviso](https://www.nviso.eu/) suggest in their articles (Android[1] and iOS[2]) and article. They have full credit over this, I will add some comments on what was not immediately clear to me:)

## Android
The general solution for Android applications is to tinker with `iptables`. As a result, all the traffic will be forwarded based on the rules we set. If we add a forwarding rule to our proxy, it's game over :) But, how can we do it? The solution we found is ProxyDroid!

ProxyDroid is an Android application that requires root privileges and modifies the IP routes in order to forward all the traffic to our desired IP address.

We can download Proxydroid from the Play Store. Remember that we need to have a rooted device to be able to run it. 

Here is the complete procedure to set up our proxying rules:
1. download the application from the Play Store (`org.proxydroid`) and install it
2. open the application and modify the parameters as shown in the Figure below. Add your laptop/PC IP address, and an available port (e.g. `8087`), and set the Proxy type to HTTP
<figure>
  <img src="/assets/android_proxydroid.png" alt="ProxyDroid setup" style="width:60%">
  <figcaption>ProxyDroid setup</figcaption>
</figure>

3. Now the application traffic is sent to our proxy server since the Flutter library cannot ignore these route changes. If the application does not implement SSL pinning, our job is done (skip the other steps). However, it is not often the case
4. Frida to the rescue! We can use this tool to bypass SSL pinning. We can download the script below, and spawn the application with `frida -U -f com.package.name -l script_name.js`
	- https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js
5. Now we should be able to intercept all the traffic or your Flutter application:)

## iOS
In iOS devices, we don't have any"ProxyDroid" like applications, so we need to find a different solution. As written in the article cited above, we can set up a wifi hotspot network or use OpenVPN to tunnel all the traffic through our proxy. I will explain the second solution since it is the only one I tried and worked for me (and it is probably the easiest one).

Here are the steps required to set up the VPN and start intercepting the traffic
1. install the OpenVPN client on your iOS device (from the App Store)
2. download in your PC the script below, and set it up to be executable (from a Linux terminal)
```bash
# download
wget https://git.io/vpn
# removes line that makes script crash in Kali
sed -i "$(($(grep -ni "debian is too old" openvpn-install.sh | cut  -d : -f 1)+1))d" ./openvpn-install.sh
# make the script executable
chmod +x ./openvpn-install.sh
# execute the script
sudo ./openvpn-install.sh
```
1. follow the guided steps and insert your PC private IP (re-enter when they ask you to enter the public one). Keep `UDP`, `1194` port, and probably default DNS is fine. Finally, add a name (it will create a file with that name inside `/root/` directory)
```
Welcome to this OpenVPN road warrior installer!

Which IPv4 address should be used?
     1) 192.168.1.4
     2) 192.168.122.1
     3) 172.17.0.1
IPv4 address [1]: 1

This server is behind NAT. What is the public IPv4 address or hostname?
Public IPv4 address / hostname [93.66.98.98]: 192.168.1.4

Which protocol should OpenVPN use?
   1) UDP (recommended)
   2) TCP
Protocol [1]: 1

What port should OpenVPN listen to?
Port [1194]: 1194

Select a DNS server for the clients:
   1) Current system resolvers
   2) Google
   3) 1.1.1.1
   4) OpenDNS
   5) Quad9
   6) AdGuard
DNS server [1]: 1

Enter a name for the first client:
Name [client]: client

```
4. start the VPN service
```bash
sudo service openvpn start
```
5. copy the configuration file from `/root/<filename>.ovpn` to your device. As suggested in the article, you can use a Python server to do that.
```bash
sudo python3 -m http.server 8081 --directory /root/
```
6. download the configuration file into your device, by connecting to http://IP:8081
7. load the configuration file into the OpenVPN client. You can do it by going to the file explorer, sharing the file and opening it with the OpenVPN client
8. back to your computer: configure your IP tables to forward all the traffic coming from the `tun0` VPN interface, to your BurpSuite listening port (`<BURP_PORT>`). Also set `<IP_SUBNET>` to your subnet (e.g. `192.168.1.0/24`, remember the `/24`)
```bash
# forward HTTP traffic
sudo iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 80 -j REDIRECT --to-port <BURP_PORT>
# forward HTTPS traffic
sudo iptables -t nat -A PREROUTING -i tun0 -p tcp --dport 443 -j REDIRECT --to-port <BURP_PORT>
sudo iptables -t nat -A POSTROUTING -s <IP_SUBNET> -o eth0 -j MASQUERADE
```

The route forwarding rules should be set by now, and we should be able to intercept the traffic of our beloved application. If you do not see any traffic, and the application seems that it is not working, the SSL pinning guards have been probably called for help.

We can bypass using the same frida script used before (it checks if we are working with Android or iOS) and start it with `frida -U -f com.package.name -l script_name.js`
- https://raw.githubusercontent.com/NVISOsecurity/disable-flutter-tls-verification/main/disable-flutter-tls.js

**Note**: when you need to reset your configuration (e.g. change the OpenVPN configuration), the only possibility I found is to remove OpenVPN (command `4`) and reinstall it again. This can mess up your OpenVPN already installed (at least in my Ubuntu machine).

To fix it, you can reinstall it with `sudo apt-get install openvpn network-manager-openvpn network-manager-openvpn-gnome`


And that's all! If you have any questions, let me know:)

# References
[1] https://blog.nviso.eu/2022/08/18/intercept-flutter-traffic-on-ios-and-android-http-https-dio-pinning/

[2] https://blog.nviso.eu/2020/06/12/intercepting-flutter-traffic-on-ios/