---
title: "My Journey Through Developing an Android App in 2023"
date: 2023-09-26T11:20:24+02:00
draft: true
categories: dev
---

Hei everyone! Since I am working in mobile application security, I thought it wuld be a great idea to develop something, in order to see this world on the other side. I will probably won't use a lot of (or any at all) critical functionalities, but I hope it will help you to learn something about Android development in 2023.

This is not my first Android app. In 2019, I developed a weather app for my dad: [MeteOrsago](https://github.com/alright21/MeteOrsago). It is quite simple but it was interesting to me because I learnt how to handle API data (from a plain TXT file 😅) and show them on screen. I was quite proud of it, but I stopped developing it after I completed the goal of the app: show weather data from my house's weather station, and other data related to my city and region in Italy.

When I started mobile security, I thought that the development was similar to it, except for the language (bye Java, welcome Kotlin), but I was unaware about Jetpack Compose and what Google developed recently. I was quite overwelmed, and I still do not know almost anything: I will probably make a lot of mistake because I haven't studied the theory a lot, but I am happy to learn from you if you have any suggestions.


## The Idea

Nowdays, I live alone in Milan. There are countless advantages compared to living with parents, but every aspect of life is now on my control: cleaning the house, do groceries, organize your weekly menu, to name a few. I love preparing my meals everyday, but I prefer to have all the weekly menu organized, with all the ingredient already in my fridge. It has two advantages: you save time (you do groceries once a week) and you save money (you do not tend to buy randomly or what you do not necessary need). That's why I came up with this idea: a mobile application that creates the weekly menu for you. One step back: no AI and nothing fancy (for now): I just want to store a collection of meals, and every week the app will create the menu (on Sunday) for the week days. In the app, you should be able to:

0. generate a random weekly menu by clicking on a button on the home page, if the menu has not been created yet.
1. see the current week menu on the home page.
2. move around different activities using a side menu
3. automatically archive old menu on the following Sunday. When this happens, the home page will have a single button to create the new menu
4. add, modify or delete meals inside a Meals activity. You should be able to see the list of the meals, and each meal should have a property `timeOfDay` to indicate if this meal is suitable for lunch or dinner (yeah, I am a bit strange)
5. see all the archived menus, in another actitity. Each menu will be identified by the current year and the week numer (1-52)

Based on this info, this is what I came up with, drawn using my old iPad Air (I am not an expert on this).

<figure>
  <img src="/assets/mobile_dev_mymenu_prototype.png" alt="MyMenu Prototype" style="width:100%">
  <figcaption>Prototype of MyMenu</figcaption>
</figure>

## Translating Ideas to Code

Thinking about an app can be quite simple, but creating it, programming it, is a bit daunting for me. Since I do not know a lot about the newest way to develop an Android app, I need some info. I also love to architect my projects in the best possible way, following guidelines and best practices: I found out that Google offers some courses directly on [developer.android.com](https://developer.android.com/). I went through their [Modern Android App Architecture](https://developer.android.com/courses/pathways/android-architecture) but I stopped because there's was a lot I didn't know anything about. It is a completely new world!

I decided to move my attention to some practical execises, and I think Android Developer's course called [Jetpack Compose for Android Developers](https://developer.android.com/courses/jetpack-compose/course) is great! Jetpack Compose offers great flexibility but you have to rethink your way of developing applications, especially on what concerns UI and UI management. For example, I learnt a lot about Composables (pieces of UI used as building blocks to create your screen), layouts and how you can place these composable following Material Guidelines, the concept of state, etc. If you are not comfortable with these concepts, I highly recommend these courses: Google has put a lot of effort in them, and they are all free!


