---
title: "FE CTF 2023"
date: 2023-10-27T16:58:25+02:00
draft: true
categories: ctf
---

# FE CTF 2023
Write-ups for [FE CTF 2023](https://play.fe-ctf.dk/). This weekend I was quite busy, but I managed to solve some easy challenges in this CTF.

- [Challenges](#challenges)
  - [Login - Level 1](#login---level-1)
  - [Login - Level 2](#login---level-2)
  - [Login - Level 4](#login---level-4)
  - [CRACKME.EXE - Level 1](#crackmeexe---level-1)

## Challenges
### Login - Level 1

| **Category** | **Points** | **Solves** |
|:------------:|:----------:|:----------:|
|   Web  |      26     |     357     |

#### Challenge Description
> So you fancy yourself a hacker? Me? I don't even see the code!
> 
> [Log in, get flag](http://login-lvl1.hack.fe-ctf.dk/)
#### Approach
The application consists of a login page. We see immediately that we get an error "Invalid Password".


<figure styple="text-align:left">
  <img src="/assets/fe-ctf_login_level_1_intro.png" alt="login intro" style="width:100%" >
  <figcaption>Login error</figcaption>
</figure>

We need to find a way to bypass this error! The first step that I do is to see the page source and see if some JavaScript is used. We are lucky because the page handle login client-side inside `static/script.js` file, and the password is hard coded there 😄 

```javascript

let error_timeout = null;

const clear_error = () => {
  document.getElementById("error").innerText = "";
};

const error = (msg) => {
  if (error_timeout) {
    window.clearTimeout(error_timeout);
  }
  document.getElementById("error").innerText = msg;
  error_timeout = window.setTimeout(clear_error, 5000);
};

window.onload = (_event) => {
  document.getElementById("form").onsubmit = (event) => {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    clear_error();
    if (username == "") {
      error("empty username");
      event.preventDefault();
    }
    else if (password != "SecureHunter2!") { // <-- Password is here
      error("invalid password");
      event.preventDefault();
    }
  };
};

```

Just insert the correct password, and we have the flag!



#### Reflection
A simple web challenge. We always need to check client-side files for secrets!

### Login - Level 2

| **Category** | **Points** | **Solves** |
|:------------:|:----------:|:----------:|
|   Web  |      41     |     292     |

#### Challenge Description
> Ha! Too easy!, I hear you say. Then try this:
> 
> [Log in, get flag](http://login-lvl2.hack.fe-ctf.dk/)

#### Approach

We have the same login page, but this time the JavaScript is different. We can see that the password is not written in plaintext, but it is encrypted. Luckily, we have the key, and the encryption algorithm, which is a simple `XOR` operation between the key and the password.

```javascript
// ...
const key = [8, 131, 214, 191, 186, 15, 133, 27, 56, 78, 231, 188];
const password_enc = "5bf6a6dac85ce0784a7d93ec69f0a5c88a7de13a";

const encrypt = (bytes, key) => {
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = bytes[i] ^ key[i % key.length];
  }
  return bytes;
};

// ...
```

How can we find the correct password? We can create a python script to decrypt it and login!

```python
key = [8, 131, 214, 191, 186, 15, 133, 27, 56, 78, 231, 188]
password_enc = "5bf6a6dac85ce0784a7d93ec69f0a5c88a7de13a"


def decrypt(bytes_data, key):
    byte_array = bytearray(bytes_data)
    for i in range(len(byte_array)):
        byte_array[i] = byte_array[i] ^ key[i % len(key)]
    return bytes(byte_array)


password_enc_bytes = bytes.fromhex(password_enc)

decrypted_password = decrypt(password_enc_bytes, key)
print(decrypted_password.decode('utf-8'))
```

<figure styple="text-align:left">
  <img src="/assets/fe-ctf_login_level_2_password.png" alt="level2 password" style="width:60%" >
  <figcaption>Result of password decryption</figcaption>
</figure>


### Login - Level 4

| **Category** | **Points** | **Solves** |
|:------------:|:----------:|:----------:|
|   Web  |      100     |     107     |

#### Challenge Description
> Let's change tactics. I've had a friend help me out with this one. She's a Full Stack DeveloperTM. Fancy that.
> 
> [Log in, get flag](http://login-lvl4.hack.fe-ctf.dk/)

#### Approach

The application does not seem to have any client-side check inside `static/script.js`. We need to use our server-side attack arsenal, and one of the first is SQL injection (the friend is a Full Stack dev right?).

We can try with simple payloads inside the admin or password text input (e.g. `admin' or 1=1--`), but we get an interesting error: "intrusion attempt detected: multiple query results".

It probably means that the attack is successful, but the database returns multiple row, which is not ideal during the login phase. We can bypass that by using `limit 1` SQL verb, so that the database returns just one row!

The final payload I used is `admin' or 1=1 limit 1--`, with a random string in the password field.


#### Reflection
A simple SQL injection with an interesting twist on the row limit!

### CRACKME.EXE - Level 1

| **Category** | **Points** | **Solves** |
|:------------:|:----------:|:----------:|
|   Rev  |     301      |     219     |

#### Challenge Description
> [crackme.exe](https://play.fe-ctf.dk/files/75b73edc8c0a2cbf04b362963bac3bc2/crackme.exe-l3v3l_o1_5233dba6c025e8e966afb49057fd658dd05fc0da.tar?token=eyJ1c2VyX2lkIjo0NywidGVhbV9pZCI6MjcsImZpbGVfaWQiOjl9.ZTy_gg.Tppv_jPunr9eZu520x8uTUEaJl0)

#### Approach

We always have to run strings on a reverse binary, and that is the solution for this challenge. I used Ghidra to load the binary and search for strings there, but `strings` will give the same results.

<figure styple="text-align:left">
  <img src="/assets/fe-ctf_crackme_level_1_flag_string.png" alt="flag string" style="width:100%" >
  <figcaption>The flag is a plain string stored inside the binary.</figcaption>
</figure>

#### Reflection
The first step into reversing.

# Credits <!-- omit from toc -->
This template was based on [RyanNgCT/CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template)


