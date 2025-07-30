> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI5NDg0ODkwMQ==&mid=2247486472&idx=1&sn=c9cc120bb8327fbca5861334c68b51e3

#  应急响应利器：Procmon 的 Boot Logging 功能如何揭露隐藏的威胁  
原创 网安布道师  格格巫和蓝精灵   2025-07-10 04:30  
  
##   
  
上一篇文章中提到了autoruns的绕过，这篇文章介绍如果绕过了autoruns该如何检查启动项  
  
在网络安全应急响应中，时间就是一切。当系统行为异常、怀疑遭受攻击时，我们需要尽快定位问题，找出攻击的蛛丝马迹。Process Monitor (Procmon) 作为 Sysinternals 工具集中的明星产品之一，其强大的 **Boot Logging（引导日志）**  
 功能，能在应急响应中发挥意想不到的作用，尤其有些恶意程序绕过autoruns检测的时候，可以帮助我们揭露那些潜伏在系统启动阶段的恶意活动。  
### 为什么 Boot Logging 在应急响应中如此关键？  
  
传统的日志分析往往在系统已经完全启动并运行后才开始。然而，许多高级持续威胁（APT）和恶意软件会利用系统启动的早期阶段进行操作，例如：  
- **持久化机制：**  
 在注册表 Run 项、启动服务、计划任务甚至驱动加载层面植入，确保每次开机都能自启动。  
  
- **隐藏活动：**  
 在安全软件完全加载之前执行恶意行为，比如删除自身痕迹、窃取敏感数据或与C2服务器通信。  
  
- **系统篡改：**  
 修改关键系统文件、注册表键值，为后续攻击做准备。  
  
这些“启动即发”的活动，常常能够绕过常规的安全监控。而 Procmon 的 Boot Logging 功能，能够提供从系统加电自检（POST）完成到桌面完全加载期间的所有文件、注册表和进程/线程活动，为应急响应人员提供了一个“上帝视角”，帮助我们捕获这些早期、隐蔽的恶意行为。  
### 如何在应急响应场景下使用 Boot Logging？  
  
在应急响应中，使用 Procmon 的 Boot Logging 功能通常遵循以下步骤：  
#### 1. 快速部署并启用引导日志  
  
当怀疑一台机器被入侵时，首先需要做的是将 Procmon 部署到目标机器上（如果尚未安装）。  
- **在 Procmon 中启用：**  
 运行 
```
Procmon.exe
```

  
，点击 **Options (选项)**  
 -> **Enable Boot Logging (启用引导日志)**  
。确认弹窗后，会提示你下次重启时生效。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9qM7NQ3lGkDswP5Bh93LNop5y9O8M1jYHgFobeiaUrPUUia0aEFHK8BjJPrTnLMLEiaOYRTuAuO22W4oMVDgGVvDg/640?wx_fmt=png&from=appmsg "")  
  
  
- **通知用户或远程重启：**  
 通知受影响的用户保存工作并重启电脑。如果远程操作，则执行远程重启命令。这一步至关重要，因为只有重启才能触发引导日志的记录。  
  
#### 2. 收集引导日志文件  
  
系统重启并登录桌面后，Procmon 会自动弹出提示，询问你是否保存引导日志。  
- **保存日志：**  
 务必选择 **Yes**  
，并将日志保存为 
```
.PML
```

  
 格式文件。建议将其命名为类似 
```
CompromisedHost_BootLog_YYYYMMDD_HHMM.PML
```

  
 的格式，方便后续溯源和管理。  
  
- **转移日志：**  
 将 
```
.PML
```

  
 文件传输到应急响应工作站进行离线分析，避免在受感染机器上进行大量分析操作，防止二次感染或数据丢失。  
  
#### 3. 深入分析日志：寻找恶意行为线索  
  
用 Procmon 打开 
```
.PML
```

  
 文件。面对海量数据，需要有针对性地进行分析：  
  
ctrl+t 可以打开进程树信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9qM7NQ3lGkCShxA9zlWRtpWWmWtDxX1yrko8GmtJEWlkkGq1KtlpeOC997ytcNhcOh9YgdcABKupzv8MMh7ZYg/640?wx_fmt=png&from=appmsg "")  
  
- **时间轴分析：**  
 恶意软件通常会在启动阶段尝试快速完成某些任务。关注时间戳，特别是在系统启动初期，哪些进程被创建、哪些文件被访问、哪些注册表键值被修改。利用 Procmon 的 **Duration (持续时间)**  
 过滤器，可以快速定位耗时异常的操作。  
  
- **关注异常进程创建：**  
  
- **Process Tree (进程树)：**  
 通过 **Tools (工具)**  
 -> **Process Tree**  
 查看进程的父子关系。异常的父子进程关系（例如，
```
explorer.exe
```

  
 启动了非用户交互的命令行工具，或者一个非系统关键进程启动了可疑的子进程）往往是恶意行为的信号。  
  
- **高权限进程：**  
 关注 SYSTEM 或 Local Service 权限下启动的非正常进程。  
  
- **注册表修改：**  
  
- 
```
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

  
  
- 
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

  
  
- 
```
HKLM\SYSTEM\CurrentControlSet\Services
```

  
 (检查异常的服务安装和启动)  
  
- 计划任务相关的注册表项。  
  
- **持久化机制：**  
 重点过滤对以下注册表路径的写入操作：  
  
- **异常配置：**  
 查找与安全软件、系统策略或网络配置相关的异常修改。  
  
- **文件系统活动：**  
  
- **可疑文件创建/删除：**  
 查找在非标准路径（如 
```
C:\Windows\Temp
```

  
、用户配置文件目录下的隐藏目录）创建的 
```
.exe
```

  
、
```
.dll
```

  
、
```
.bat
```

  
、
```
.ps1
```

  
 等可执行文件。  
  
- **关键系统文件访问：**  
 监测对 
```
ntdll.dll
```

  
, 
```
kernel32.dll
```

  
, 
```
user32.dll
```

  
 等核心 DLL 文件或 
```
winlogon.exe
```

  
, 
```
lsass.exe
```

  
 等关键进程的非正常访问或注入尝试。  
  
- **网络连接证据：**  
 尽管 Procmon 主要记录本地活动，但某些文件和注册表操作会间接揭示网络通信意图（例如，对代理设置的修改，或某些连接配置文件的生成）。  
  
- **过滤器的灵活运用：**  
  
- **Operation is WriteFile 或 RegSetValue：**  
 查找写入操作。  
  
- **Path contains "temp" 或 Path ends with ".exe"：**  
 缩小文件范围。  
  
- **Process Name is "powershell.exe" 或 Process Name is "cmd.exe"：**  
 关注命令行工具的使用，因为它们常被恶意软件利用。  
  
- **Result is "ACCESS DENIED"：**  
 有时，恶意软件尝试访问受保护资源被拒绝，也能提供线索。  
  
### 结合其他工具  
  
Procmon 的 Boot Logging 并非万能，它应该与其他应急响应工具结合使用：  
- **内存取证：**  
 对于更深层次的内存注入或无文件恶意软件，Volatile、Rekall 等工具能提供更全面的视图。  
  
- **网络流量分析：**  
 结合 Wireshark、IDS/IPS 日志，分析启动阶段是否有异常的C2通信。  
  
- **沙箱分析：**  
 将可疑文件放入沙箱环境中运行，观察其行为。  
  
### 总结  
  
Procmon 的 Boot Logging 功能，为应急响应人员提供了一道独特的“时光回溯”能力，让我们能够洞察系统在最脆弱的启动阶段所发生的一切。掌握这项技能，能够极大地提升我们发现、分析和遏制早期恶意行为的能力，从而在与攻击者的赛跑中占据主动。  
  
在你的应急响应实践中，Procmon 的 Boot Logging 是否帮助你揪出过隐藏的威胁？欢迎在评论区分享你的实战经验！  
  
  
