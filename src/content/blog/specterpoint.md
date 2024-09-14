---
title: "SpecterPoint"
description: "The Rust C2 Server"
pubDate: "Sep 10 2024"
heroImage: "/specterpoint/specterpoint.jpg"
tags: ["rust", "c2", "malware"]
---

See the repo here, [SpecterPoint](https://github.com/zurtix/SpecterPoint">SpecterPoint)

I'd imagine if you're clicking on this post you're wondering what is SpecterPoint - well I'll tell you. Welcome to my interpretation and development of a C2 server. Accompanied by a client, server, and agent, where I try to write as much in Rust as possible. Currently the only thing not written in rust is part of the client, as it's using typescript for UI components.

## What is a C2 server?

A C2, or also known as a Command and Control server, is a tool used in the vast arsenal of a threat actor. Actors will use C2 servers to communicate with infected hosts to, establish persistence, gather intel, deploy malware, or become a zombie as part of a botnet. Command and Control infrastructure is really neat, as it allows for an unorthodox method of controlling a host outside of the norms of something like RDP or SSH. Ideally this activity is well hidden making it difficult to detect. Check out these articles if you want to learn more about C2s.

[https://www.sentinelone.com/cybersecurity-101/threat-intelligence/what-are-command-control-c2-servers/](https://www.sentinelone.com/cybersecurity-101/threat-intelligence/what-are-command-control-c2-servers/)
[https://www.malwarepatrol.net/command-control-servers-c2-servers-fundamentals/](https://www.malwarepatrol.net/command-control-servers-c2-servers-fundamentals/)

## Why a new C2, am I worried about who will use it?


What better way to learn how to understand and fight against a C2 than to create one. Lately I've been in this mode of writing malicious things to better understand it. Write code, reverse it, identify how it works, build against it. C2 servers have always been a little bit of mystery to me because I've seen a fair share of poorly implemented ones. Now I am not saying mine is well implemented, I plan to constantly add features to it when and if I can, but I'm starting small.


Which leads me to my next thing - am I worried about the possibility of threat actors using it? Well of course, but my code is no different than the existing other repos out there on git already. However, I would like to take this time to mention that this C2 is for purely educational and ethical purposes only.


## The First Design Ideally 


So as I was planning to build this, I had an original design idea in mind. Build something capable of hosting multiple endpoint and listeners, support for deploying several servers that would feed information back to the client.


![initial design](/specterpoint/initial_design.png)

Not too shabby right? Relatively simple design, maybe a little on the over engineered side, but I do love buidling highly availability and redundant applications, and with good reason which we will talk about later on. From what we can see of this first design, we have a single client capable of communicating with the server, ideally this will be to add new listeners and send tasks to agents. We also have agents that will also communicate with the servers to send task results and any other information we want.

## Getting Started


With every new project, I always find the hardest part is getting started, and this project was no different. So I thought to myself, what should I do first just to really get myself going. Easy! I'll do the thing I enjoy the least - making things pretty. With the idea that I really wanted to keep rust for all aspects of the tool, I decided to use [Tauri](https://tauri.app/).


Why Tauri and not [Dioxus](https://dioxuslabs.com/) - well, Dioxus would have given me the opportunity to write more rust and both frameworks use a web view to render the UI. But if I'm being honest, I really wanted to upgrade my web development skills and using Tauri offered that. Tauri allowed me to write a lot of my client side code in TypeScript while still offering a rust backend. Thanks to this I got to experience and play with some libraries like [TanstackRouter](https://tanstack.com/router/latest/docs/framework/react/overview), [TanStack Form](https://tanstack.com/form/latest/docs/overview), [Shadcn](https://ui.shadcn.com/), and [Tailwind CSS](https://tailwindcss.com/). But I wouldn't be surprised if I decide to swap over to Dioxus at some point just to learn and experiment with the library.


In addition to the UI, I had to think of a way of how I wanted to store my data for the client and server. Both the client and the server would require holding on to important information such as listener configurations, users, passwords, etc. And I didn't want to leverage something too heavy and unecessary like postgres, so I settled with  [SQLite](https://www.sqlite.org/). SQLite was a no brainer due to it's lightweight design and especially since it works so well with Rust leveraging the [SQLx](https://github.com/launchbadge/sqlx) library. If you enjoy a non-orm based library, I highly recommend SQLx.


Now let's talk a little about the server design. The main goal of the server is to act as an API endpoint, but also as a proxy for any communcations back and forth with the agents. Why distinctly mentioned the difference? Well, our API will handle things like creation of new listeners and endpoints, starting and stopping listeners as our client pleases, and allow multiple users to connect and manage the servers. The proxy piece comes naturally as we build out our server, it is the middle man in terms of communication between the agent and the client. As we add new tasks from the client, we will expect a result of those tasks to be sent back to the client and possibly leak our information. Of course, we wouldn't want to have some bad [OPSEC](https://www.fortinet.com/resources/cyberglossary/operational-security) by sending results from the agent back directly to the client, best way to do so is leveraging the server for those communications between agent and client. If we are really concerned with the OPSEC from even our client to our servers, we could use things like VPNs, proxies, hosting the client on some environment we aren't directly associated with etc.

That was quite the mouth full of words to get some minor details out of the way. Since I have not quite figured out my design in terms of the agent - yet. I will move past this for now and apologize, If you are reading this, come back soon and hopefully I will have the agent design up. For now enjoy the rest of the write up!


## The Client UI


For the client I wanted to encompass the feel of familiarity, playfulness, but at the same time, some cool dark theme that worked with a logo. Now I must admit, the ghost logo that you'll see in specterpoint was ripped off the web, I did not make it, but I find it very fitting. Feel free to skip this part if it's of no interest to you, but let me explain some of the main components of the UI and how I have things laid out.


![client wireframe](/specterpoint/client_design.png)

### Agents


This section of the UI will be home to all agents that connect. It will be dynamically populated while the client is open. Each agent will appear with an ID along with a last seen date to keep the user informed.


### Command / Shell


Each agent that is interacted with will have the option to select a command like terminal or a reverse shell. The Command based terminal will provide users with simple commands that can be issued out to each agent, things like download a file, upload file, etc. The reverse shell will be capable of achieving a full shell on the desired system, much like how you would obtain when using SSH to connect to a host.


### Event / Logs


I'm very proud of this section as it provides a real time look into logs from the servers or any events occuring from the agents. The event and logs component consists of a TCP stream of events and is refreshed as new events hit the socket on the backend. I'll share more details into how this works later in the blog.


### Menu


Last but not least, the menu. Arguably one of the most simple, yet most important components. This menu was designed to open similar to the Windows start menu or XFCE application launcher if you're more familiar with Linux. The menu consists of navigational properties in order to switch through the various - pages - that the application provides for configuring.


If you're looking for a more indepth and detailed overview of the UI and how it is used. Please see the [Wiki](https://github.com/zurtix/SpecterPoint/wiki) associated with the GitHub repo.

Under construction
