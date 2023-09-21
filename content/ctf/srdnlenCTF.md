---
title: "SrdnlenCTF"
date: 2022-10-12T23:08:58+02:00
draft: false
categories: ctf
---

# SrdnlenCTF
Writeups for [srdnlenCTF](https://ctf.srdnlen.it/)

## Categories
**Web**
-  [I love pickles](#i-love-pickles)

## Challenges
### I love pickles

| **Category** | **Points** | **Solves** |
|:------------:|:----------:|:----------:|
|   Web  |      50     |     51     |

**Challenge Description**: My Sardinian friend says she hates "su cugumere cunfettau", but I love them, on top of my burger and in my code.  
  
If you really know your pickles you can enter in my admin area.  
  
Website: [http://ilovepickles.challs.srdnlen.it](http://ilovepickles.challs.srdnlen.it/)

#### Approach
As the name of the challenge suggests, the application should use the `pickle` library to encode and decode the cookies (I found out about this library while I was playing the sekaiCTF, but I didn't solve the challenge there). It uses method `loads` to decode a cookie string and `dumps` to encode it back. The cookie is also base64 encoded.

**Steps**
1. The first thing to do is to extract the cookie used by the website
{{< figure src="/assets/srdnlen-CTF.png" caption="Cookie encoded with `pickle` library" >}}
2. I created a python script (see the complete code at the end) to decode the cookie. I noticed that an object called User is used, since the script complained about a `class 'User'`
3. After that, I tried to find out the attributes of the object. I used the VSCode python debugger to navigate the object (printing the object only showed the pointer details)
{{< figure src="/assets/srdnlen-CTF-1.png" caption="`User class` content shown in python debugger" >}}
4. Finally, I changed the value of `user_type` to `admin` and encoded the final object
5. I substituted the cookie with the crafted one, refreshed the page, and obtained the flag (`/flag` endpoint)

```python
import pickle
from base64 import b64decode, b64encode

class User:
    pass

cookie = "gASVNAAAAAAAAACMCF9fbWFpbl9flIwEVXNlcpSTlCmBlH2UjAl1c2VyX3R5cGWUjAlBbm9ueW1vdXOUc2Iu"
user = pickle.loads(b64decode(cookie))
user.user_type = 'admin'
print(b64encode(pickle.dumps(user)))
```
#### Reflection
The challenge was easy, but you need to understand a bit how `pickle` library works. It also supports encryption, which needs a secret key, so keep in mind that if you cannot decode the cookie properly.

---


# Credits
This template was based on [RyanNgCT/CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template)