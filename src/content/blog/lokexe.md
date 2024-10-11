---
title: 'Lok.exe RAT Malware'
description: 'RAT Malware - Additional information TBD'
pubDate: 'Oct 10 2024'
heroImage: '/lokexe/lokexe.png'
tags: ['malware', 'rat', 'c++']
underConstruction: true
---

## Lok.exe Malware


Opening the sample in `Detect It Easy` we can see some key information. The sample is written in C++, specifically utilising `Borland`. If you aren't aware what `Borland` is-it's an older IDE (Integrated Develop Environment) and compiler, a sucecssor to `Turbo`, for Windows. In addition to the usage of Borland, we can also see that this sample was created using `Inno Setup`. `Inno Setup` is a tool to create an installer package. Think of any software you've ever installed. Some software will require you to accept terms of agreement, you'll hit next a bunch of times, until finally you can click `Install`. Well `Inno Setup` provides that feature set, where you can specify what gets installed. See more about it here, https://jrsoftware.org/isinfo.php 

![Detect It Easy](/lokexe/detect_it_easy.png)

Opening the sections of the PE in Detect It Easy, if we navigate to the `.data` section we will see in the first few bytes `Embarcadero`. Since having never heard of this, I switched over to google to do some investigating. It appears that the `RAD` software is an IDE for C++ for building native apps. This gives us a bit more information on how this malware was possibly built.

https://www.embarcadero.com/

![Embarcadero](/lokexe/embarcadero.png)


Since we've seen relations to `Inno Setup` piece, we can use `InnoUnpacker` as a means to determine if it's possible to extract it's inner data. However, it appears that the `Inno Setup` is corrupt, or maybe even encrypted.

Get `InnoUnpacker` GUI or CLI tools here, https://www.rathlev-home.de/index-e.html?tools/prog-e.html#unpack

![InnoUnpacker](/lokexe/inno_unpacker.png)

With no much to go off of, let's open `Resource Hacker` to see what we can find.

On initial inspection of the resources, a rather odd looking `PNG` is present in the `RPL` directory. At the moment I am not sure what to make of this. It's possible this may be some encrypted data represented with `PNG`  magic bytes in a file?

![Weird PNG RPL](/lokexe/weird_png_rpl.png)

In addition to all the above, since we have information around the original file name, it's version, and company, we can search the web for relevant information. This will help give us an idea between expected and unexpected behaviours. As a result I came across the following URL, https://donutsoft.org/. After downloading the portable and installers from this site into my analysis VM, I saw some differences. 

We can see that the installer actually executes some sort of `Inno Setup`, compared to our malware, which just executes as we will see within the Dynamic Analysis section.

![Donutsoft Setup](/lokexe/donutsoft_setup.png)

If we take a look at the portable version, we can find all related resources and libraries accompanied with it.

![Donutsoft Portable](/lokexe/donutsoft_portable.png)

And based on this portable version we get the similar and expected results as we can see based on their web page.

![Donutsoft Tray Button](/lokexe/donutsoft_tray_button.png)

What was interesting between the actual installer and portable version in comparison to the malicious file is that there is not instance of `RPL` resource.

Setup version

![Donutsoft Setup non Malicious](/lokexe/donutsoft_setup_non_malicious.png)

Portable version

![Donutsoft Portable non Malicious](/lokexe/donutsoft_portable_non_malicious.png)

Malicious file

![Malicious Resources](/lokexe/malicious_resources.png)

## Dynamic Analysis

Before jumping into looking at the code and how it's structured, I am going to take the approach of running some dynamic analysis. In doing so, this may or may not give us some idea of how the malware executes, what it creates, and so on. I find this step helpful, especially when it comes to malware written in C++ leveraging windows API libraries. 

Remember, when doing Dynamic Analysis it's important that connections outbound are severed. Since we don't understand how this malware behaves, it's ideal to not let it communicate out. In addition, make sure that snapshots are being leveraged to revert back to previous states. Once we execute the malware, we don't want to have to rebuild our analysis VM over and over again.

Reviewing the sample again, we will want to make sure this file is named appropriately with what the original file name was. This ensures that any anti-analysis techniques based on the file name itself will not prevent it from executing. As we can see `TrayButton.exe` is the original file name.

![Detect it Easy Original File Name](/lokexe/detect_it_easy_original_file_name.png)

![Sample Renamed](/lokexe/sample_renamed.png)

Before executing the malware, a few tools need to be setup prior to.

##### Process Monitor with Filter

Process monitor will need to be configured with the appropriate filter and started prior to the execution of the sample.

![Process Monitor Filter](/lokexe/process_monitor_filter.png)

##### Process Explorer

Helpful in identifying new processes opening and investigating their threads, creating dumps, reviewing TCP etc.

![Process Explorer](/lokexe/process_explorer.png)
##### FakeNet-NG

FakeNet will be utilised in order to intercept any potential calls made out by the malware to C2 servers as well as assist in identifying any payload that may be useful to our RE.

![FakeNet Startup](/lokexe/fakenet_startup.png)

##### Regshot

Regshot will need to take it's first shot of the registry prior to execution of the sample. Ideally to prevent additional noise you will want to make sure that all your analysis tools are open prior to taking the first shot. Note: Regshot can take some time to process, just be patient.

![RegShot](/lokexe/regshot.png)

### Reviewing Tool Results

With all of our tools setup, we can now being executing our sample and reviewing the results.

Review Process Explorer first, since if we are not quick enough we will see some of the processes terminate themselves, we can see `TrayButton.exe` being executed following the creation of `more.com` and `conhost.exe`.

![Procexp Start](/lokexe/procexp_start.png)

![Process Explorer More](/lokexe/process_explorer_more.png)

While letting the malware run for a short while, we can take our second RegShot. Once the second Regshot is complete, we can run a compare to identify any changes made by the malware.

![RegShot Compare Metrics](/lokexe/regshot_compare_metrics.png)

Taking a look at the RegShot compare values under keys added. We can see some strange behaviour. It appears the malware creates a new schedule task.

![RegShot Results](/lokexe/regshot_results.png)

We can confirm this by opening the windows `Task Scheduler`. After reviewing the task scheduler we can see the newly created `AsusFCNotification` task.

![Task Scheduler New Task](/lokexe/task_scheduler_new_task.png)

Reviewing the `Actions` section of this scheduled task, we can see a path to an executable that the malware may be using in order to create persistence.

![Task Scheduler Actions](/lokexe/task_scheduler_actions.png)

After reviewing the directory where this program is being stored, we can certainly see that it contains the same icon as well as matching hashes. Which would certainly confirm our suspicion surrounding creating persistence.

![Hashed Files](/lokexe/hashed_files.png)

From Process Monitor we can see the newly created PID `4012`. We will use this PID later as a parent PID to identify additional behaviours.

![Process Monitor Execution](/lokexe/process_monitor_execution.png)

Reviewing more of the results within Process Monitor we can also see the following,

Creation of the `more.com` file in the `C:\Windows\SysWOW64\` directory 

![Process Monitor Create More](/lokexe/process_monitor_create_more.png)

Create of a temporary file `9de8dd4f` containing byte data

![Process Monitor Temp Data](/lokexe/process_monsitor_temp_data.png)

Before pivoting to filtering on the parent PID value `4012`, we can export all the data within Process Monitor as a csv file. Since we are dealing with so many events we can switch to  `procdot`, to make things a little easier. `ProcDot` is a tool to get a visual representation of the monitoring that has taken place within Process Monitor.

Taking a look at `ProcDot` we can select the PID associated with `more.com` and review it's processes. With this we can now see the previously mentioned task creation for the window task scheduler in order to create persistence. 

![ProcDot More](/lokexe/procdot_more.png)

Finally, looking at our FakeNet logs, we can see that a call was made out on behalf of `MSBuild.exe` to the IP and port `213.109.202[.]97:15647` via a raw TCP socket. We can also see that along with this call a json payload was sent within the frame, containing a `Type` of `AfkSystem`.

![FakeNet Request](/lokexe/fakenet_request.png)

## Debugging & Reversing

For this next step we will configure some DLLCharacteristics using `CFF Explorer`. We will need to modify these characteristics to ensure that the DLL does not move. In doing so we will be able to follow along within Ghidra at the same base memory address. This will make it easier as we walk through the code to identify where exactly we are within the debugger in comparison to the decompilation. Once these changes have been made we can save our new version to the desktop and open within `x32dbg` and `Ghidra`.

![CFF Explorer](/lokexe/cff_explorer.png)

As indicated from our previous step. If we take a look at the entry point within both `x32dbg` and `Ghidra` we can see that they align.

![x32db Entry](/lokexe/x32_entry.png)

![Ghidra Entry](/lokexe/ghidra_entry.png)

Following the code paths we will eventually stumble upon enumeration of the CPU information. As we can see based on the value of `EAX` being `0` we result in the values as defined here, https://www.felixcloutier.com/x86/cpuid#input-eax-=-0--returns-cpuid%E2%80%99s-highest-value-for-basic-processor-information-and-the-vendor-identification-string
Meaning the sample has successfully identified we are on an `intel` processor.

![CPUID EAX 0](/lokexe/cpuid_eax_0.png)

If we were to look in Ghidra at this specific moment in time, we would see that the debugger correlates.

![Ghidra CPUID EAX 0](/lokexe/ghidra_cpuid_eax_0.png)

Investigating the previous references to the `FUN_0042ccf0` call, we can find ourselves within a do while loop. This loop will result in the evaluation of `cpuid` from `0x0` to `0x7`, providing an much larger enumeration of the CPU info.

![ENUM CPU 0x1 to 0x7](/lokexe/enum_cpu_0x1_0x8.png)

The below table will explain the various values associated with the `EAX` register parameters.

| EAX  | Result                                                                                                                                                                                                                                                                  |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0x00 | [Returns CPUID’s Highest Value for Basic Processor Information and the Vendor Identification String](https://www.felixcloutier.com/x86/cpuid#input-eax-=-0--returns-cpuid%E2%80%99s-highest-value-for-basic-processor-information-and-the-vendor-identification-string) |
| 0x01 | [Returns Model, Family, Stepping Information](https://www.felixcloutier.com/x86/cpuid#input-eax-=-01h--returns-model--family--stepping-information)                                                                                                                     |
| 0x02 | [TLB/Cache/Prefetch Information Returned in EAX, EBX, ECX, EDX](https://www.felixcloutier.com/x86/cpuid#input-eax-=-02h--tlb-cache-prefetch-information-returned-in-eax--ebx--ecx--edx)                                                                                 |
| 0x03 | Reserved - Processor Serial Number                                                                                                                                                                                                                                      |
| 0x04 | [Returns Deterministic Cache Parameters for Each Level](https://www.felixcloutier.com/x86/cpuid#input-eax-=-04h--returns-deterministic-cache-parameters-for-each-level)                                                                                                 |
| 0x05 | [Returns MONITOR and MWAIT Features](https://www.felixcloutier.com/x86/cpuid#input-eax-=-05h--returns-monitor-and-mwait-features)                                                                                                                                       |
| 0x06 | [Returns Thermal and Power Management Features](https://www.felixcloutier.com/x86/cpuid#input-eax-=-06h--returns-thermal-and-power-management-features)                                                                                                                 |
| 0x07 | [Returns Structured Extended Feature Enumeration Information](https://www.felixcloutier.com/x86/cpuid#input-eax-=-07h--returns-structured-extended-feature-enumeration-information)                                                                                     |

Additional processor enumeration.

![Get Processor Information](/lokexe/get_processor_information.png)


## <span style="color:orange">The remainder of this page is under construction. Stay tuned!</span>


## Indicators

| Type    | Value                                                            |
| ------- | ---------------------------------------------------------------- |
| IP:PORT | 213.109.202[.]97:15647                                           |
| MD5     | 2afbe1369dd12cc3264a4b4c332396b0                                 |
| SHA1    | 06b730230788c3f066f634a0c2a499e961180e26                         |
| SHA256  | 1cad1f43e4768f56d68bb2b2737b7f5eebe78e8737f38bc6fc8dc06c595a08ad |

