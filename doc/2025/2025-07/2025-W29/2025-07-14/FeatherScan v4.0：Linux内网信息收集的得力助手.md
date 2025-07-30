> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxOTM2MDYwNg==&mid=2247515305&idx=1&sn=be2ecb1bdf90f39202e97d1e6b1deea8

#  FeatherScan v4.0：Linux内网信息收集的得力助手  
原创 子午猫  网络侦查研究院   2025-07-14 12:09  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bujwd3M0M1ICStsbhAHWtth8dQwoBBFoNDafDAzGbm1sCA8bqVWIjs40A8lu9rtuD4yeOOwDNadg/640?wx_fmt=png "")  
  
  
  
在渗透测试领域，针对Linux系统的内网信息收集与特权提升检测是一项极为重要却又繁琐的工作。平日里，渗透测试人员常常需要手动输入各种命令来完成基本的信息收集任务，不仅操作繁琐，而且效率低下。基于这样的背景，一款名为FeatherScan v4.0的工具应运而生，它为解决这些痛点提供了有效的方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALplHl5PULSG90Mh0vD5WicO09ISYLXibuWW950cj7V0kPd0oLNHQmnPFGA/640?wx_fmt=png&from=appmsg "")  
  
## 0x01 工具诞生的背景与初衷  
  
在实际的渗透打靶过程中，手动进行信息收集着实令人头疼。想象一下，每次测试都要重复输入大量命令，从获取操作系统信息到检查网络配置，从分析用户权限到查找敏感文件，一系列操作下来，耗费了大量时间和精力。而且，一旦环境较为复杂，还容易出现疏漏。  
  
考虑到一些特殊的测试环境，如不能上网的内网环境，接入AI的工具在进行信息收集和权限提升分析时会受到极大限制。因此，FeatherScan v4.0选择了完全在目标机器本地执行的方式，这样既保证了执行速度，又提高了渗透测试效率。它类似于fscan工具，需要上传到目标靶机上运行。后续，开发者还计划增加离线的POC和漏洞库，以实现对Linux系统更全面的信息收集和特权提升检测。这款工具的代码量达到3000多行，历经大半个月精心编写而成。  
##   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALp8JccHFdiatcE8RkGicrsYOtrxvf6h55UCeOVKibVOdfmm9mt4UgoAbVLQ/640?wx_fmt=png&from=appmsg "")  
## 0x02 工具概述  
  
FeatherScan是一款专门为Linux系统量身打造的自动化内网渗透与特权提升扫描工具，由泷羽Sec的作者白小羽精心开发。其核心目的在于简化渗透测试中内网信息收集和提权检测这两个关键环节，通过自动化扫描，大幅减少手工操作所花费的时间，助力安全研究人员更高效地识别系统中存在的弱点。  
## 0x03 主要功能解析  
### 全面系统信息收集  
  
FeatherScan具备强大的系统信息收集能力，涵盖多个重要方面。它能够精准获取操作系统与内核信息，让使用者清晰了解目标系统的基础架构；深入分析用户与组权限，排查潜在的权限风险；对环境变量进行深度检查，不放过任何可能隐藏的攻击向量；获取网络配置与路由信息，掌握网络拓扑结构；细致审计敏感文件权限，及时发现敏感文件的异常权限设置；检测容器环境，确保容器的安全性；全面分析服务与进程，了解系统中运行的各项服务和进程状态。  
  
此外，该工具还能进行简单的内核提权漏洞检测，这对于打靶机学习来说是非常实用的功能，能够帮助使用者快速发现一些常见的内核提权漏洞，提升对系统漏洞的认知和利用能力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpx2HSibDw2tM3B21WOQT3hPFbhictCicRLzdOmfQmmMhvibhk2E3GaCrHtg/640?wx_fmt=png&from=appmsg "")  
### 内网渗透扫描  
1. **主机发现**  
：采用混合扫描技术，将ICMP Ping、ARP分析以及TCP端口扫描有机结合，同时具备三种网络模式扫描功能。这种全方位的扫描方式极大地提高了主机发现的准确性，确保不会遗漏任何一个内网机器。在复杂的内网环境中，不同的网络模式和扫描技术可以应对各种网络配置和防护机制，有效发现隐藏在网络中的主机。  
  
1. **端口扫描**  
：支持对常见服务端口的识别。通过对目标主机开放端口的扫描和分析，能够快速确定目标系统上运行的服务类型，为后续的渗透测试提供重要线索。例如，识别出开放的SSH端口，就可以进一步针对SSH服务进行安全检测和攻击尝试。  
  
1. **服务识别**  
：自动检测开放服务及其版本信息。了解服务的具体版本对于评估服务的安全性至关重要，因为不同版本的服务可能存在不同的已知漏洞。通过准确识别服务版本，渗透测试人员可以针对性地查找相关漏洞信息，制定更有效的攻击策略。  
  
1. **隐身模式**  
：提供慢速扫描功能，以此避免触发IDS/IPS。在进行渗透测试时，目标系统往往部署了入侵检测系统（IDS）或入侵防范系统（IPS），一旦扫描行为被检测到，可能会导致测试被中断或引起目标系统管理员的警觉。隐身模式通过降低扫描速度，减少扫描行为的特征性，从而降低被检测到的风险，使渗透测试能够更隐蔽地进行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpeBKqVmUDY2dqkkRfatuqpuHicQoZQzvfBcjr84UnibBqEsj3AibDmEAZA/640?wx_fmt=png&from=appmsg "")  
### 横向移动检测  
1. **SSH密钥重用检测**  
：检查网络中是否存在SSH密钥重用的情况。如果多个主机使用相同的SSH密钥，攻击者一旦获取其中一个主机的权限，就可以利用该密钥轻松访问其他使用相同密钥的主机，从而实现横向移动。FeatherScan能够有效检测这种风险，帮助安全人员及时发现并解决潜在的安全隐患。  
  
1. **密码爆破**  
：支持对SSH、MySQL、PostgreSQL、SMB等多种常见服务进行密码爆破。在渗透测试中，密码爆破是获取系统权限的一种常见手段。FeatherScan提供了对多种服务的密码爆破功能，并且可以选择隐蔽爆破方式，虽然速度相对较慢，但能降低被发现的风险。  
  
1. **SMB共享匿名访问检测**  
：检测SMB共享是否存在匿名访问的情况。匿名访问SMB共享可能导致敏感信息泄露，FeatherScan能够及时发现这种不安全的配置，提醒安全人员采取相应措施。  
  
1. **数据库服务爆破**  
：针对数据库服务进行密码爆破，帮助渗透测试人员获取数据库的访问权限。数据库往往存储着大量敏感信息，获取数据库权限对于进一步渗透和数据获取具有重要意义。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpxzFtZcke6EiaA5uibYPGK7hf0eqssCX4DeVaXEQp1LcrdicYW2R3zBFKg/640?wx_fmt=png&from=appmsg "")  
### 特权提升检测  
1. **SUID/SGID危险文件检测**  
：扫描系统中的SUID（Set User ID）和SGID（Set Group ID）文件，并识别其中存在风险的程序。SUID和SGID文件在执行时会以文件所有者或所属组的权限运行，如果这些文件存在漏洞，攻击者可能利用它们获取更高权限。FeatherScan能够精准检测这些危险文件，为系统安全提供保障。  
  
1. **sudo权限深度分析**  
：深入分析sudo权限的配置情况，查找其中可能存在的安全弱点。sudo权限允许普通用户以root权限执行特定命令，如果sudo权限配置不当，可能会被攻击者滥用，从而获取系统的最高权限。FeatherScan通过对sudo权限的深度分析，帮助安全人员发现并修复这些潜在风险。  
  
1. **可写路径检查**  
：检查系统中存在的可写路径，因为某些可写路径可能被攻击者利用来植入恶意程序或进行权限提升。例如，攻击者可以在可写路径中创建恶意脚本，并通过特定方式使其在系统运行时被执行，从而获取更高权限。FeatherScan能够及时发现这些可写路径，提醒安全人员采取相应的防护措施。  
  
1. **内核漏洞匹配**  
：对脏牛、脏管道等常见的内核漏洞进行匹配检测。内核漏洞是系统安全的重大隐患，一旦被利用，可能导致系统完全被控制。FeatherScan内置了对常见内核漏洞的检测机制，能够快速发现系统是否存在这些高危漏洞。  
  
1. **密码哈希分析**  
：对系统中的密码哈希进行分析，尝试破解密码。虽然密码哈希破解并非总是能够成功，但在一些情况下，通过分析密码哈希可以获取有用的信息，例如密码的强度、是否使用了常见密码等，从而帮助安全人员评估系统的密码安全性。  
  
1. **自动化漏洞利用**  
：在不需要联网的情况下，实现自动化漏洞利用。这一功能使得渗透测试人员在离线环境下也能够尝试利用检测到的漏洞获取系统权限，进一步提高了工具的实用性和适应性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpmOMF2RUuEokQL1o5RmqtgZ4iaYEsMoiaxW5WXuEfYib0Mm4VENibWKrjfA/640?wx_fmt=png&from=appmsg "")  
### 安全痕迹管理  
1. **自动备份/恢复修改文件**  
：在进行渗透测试过程中，对修改的文件进行自动备份，以便在测试结束后能够恢复文件的原始状态，避免对目标系统造成永久性影响。同时，在需要时可以方便地恢复备份文件，确保系统的正常运行。  
  
1. **安全删除临时文件**  
：采用7次覆盖的方式安全删除临时文件。这种多次覆盖的删除方式可以有效防止已删除文件被恢复，保护测试过程中的敏感信息不被泄露。  
  
1. **命令历史清除**  
：清除在目标系统中执行的命令历史记录，避免这些记录成为攻击者或其他未经授权人员获取渗透测试信息的途径。  
  
1. **日志文件清理**  
：清理系统中的日志文件，减少渗透测试过程在日志中留下的痕迹。日志文件通常记录了系统的各种活动，清理日志可以降低被目标系统管理员发现渗透测试行为的风险。  
  
1. **内存缓存清除**  
：清除内存缓存中的相关信息，进一步消除渗透测试过程中留下的临时数据。  
  
1. **本地爆破记录删除**  
：删除本地的密码爆破记录，防止这些记录泄露渗透测试的信息和目标系统的潜在安全弱点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALp3wfIKs1AhSibEsqGhnf4wiaCbA5ejmzBcTsAAiaFDM9qDRr9bc3YcNpgw/640?wx_fmt=png&from=appmsg "")  
## 0x04 技术特点剖析  
### 智能交互式扫描  
1. **动态启用深度检查**  
：根据用户的选择，动态决定是否执行深入检查。在普通检查模式下，工具能够快速检测常见的提权向量，如SUID、可写文件、内核漏洞等。而当用户选择深入检查时，工具会在普通检查的基础上，增加服务爆破和敏感文件深度扫描等功能，全面深入地检测系统的安全风险。  
  
1. **按需开启内网渗透扫描**  
：用户可以根据实际需求决定是否执行内网渗透扫描。这种灵活性使得工具能够适应不同的测试场景和需求，避免在不需要内网渗透扫描的情况下浪费时间和资源。  
  
1. **交互式服务爆破确认**  
：在进行服务爆破时，采用交互式方式，让用户确认是否进行爆破操作。这一设计可以避免误操作导致的不必要风险，同时也让用户能够根据实际情况灵活调整爆破策略。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALp73vUKibfX7GeVgrVN6jz5QKVj695lEah515V5cPv6IC0iaG0Cvgj8XUw/640?wx_fmt=png&from=appmsg "")  
### 混合扫描技术  
  
综合运用ICMP Ping扫描、ARP缓存分析、TCP端口扫描以及服务指纹识别等多种扫描技术。ICMP Ping扫描可以快速发现网络中存活的主机；ARP缓存分析能够获取局域网内主机的MAC地址等信息，进一步了解网络拓扑；TCP端口扫描则用于确定主机开放的端口，识别运行的服务；服务指纹识别则能够准确判断服务的类型和版本。多种技术的结合使用，大大提高了扫描的准确性和全面性，能够更有效地发现内网中的各种信息和潜在风险。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpib3RaaOZWauVgYGr9SdKDnLKA1Yrs1wWibEuVb0JmgdIV5nrs7bbaITg/640?wx_fmt=png&from=appmsg "")  
### 权限提升自动化  
1. **自动添加特权用户**  
：在满足一定条件下，能够自动添加特权用户，为进一步的渗透测试提供便利。例如，在成功利用某些漏洞后，工具可以自动创建具有更高权限的用户，方便渗透测试人员进行后续操作。  
  
1. **sudo权限自动化配置**  
：对sudo权限进行自动化配置，优化权限设置，以满足渗透测试的需求。同时，也可以检测sudo权限配置中存在的问题，并提供相应的修复建议。  
  
1. **定时任务注入**  
：能够注入定时任务，实现一些自动化的操作。定时任务可以在指定的时间间隔内执行特定的命令或脚本，例如定期收集系统信息、执行漏洞检测等，提高渗透测试的效率和自动化程度。  
  
1. **内核漏洞EXP自动下载**  
：针对检测到的内核漏洞，自动下载相应的漏洞利用程序（EXP）。这一功能使得渗透测试人员无需手动寻找和下载EXP，节省了时间和精力，同时也提高了漏洞利用的成功率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpU9Oj2chAf7O4lFw2k40J070OHhYXgNpkUI6s8Y76bF9SWMJFhCgMwQ/640?wx_fmt=png&from=appmsg "")  
### 安全痕迹管理  
1. **操作全程跟踪记录**  
：对工具在目标系统上执行的所有操作进行全程跟踪记录，以便用户在测试结束后能够详细了解工具的运行情况和操作过程。同时，这些记录也可以作为安全审计的依据，帮助安全人员分析测试过程中是否存在潜在风险。  
  
1. **多轮覆盖安全删除**  
：在删除文件时，采用多轮覆盖的方式进行安全删除，确保文件数据无法被恢复。这种安全删除方式可以有效保护测试过程中的敏感信息，防止其被泄露。  
  
1. **服务专用日志清除**  
：针对不同服务的日志文件，进行专门的清理操作。不同服务的日志文件格式和存储位置可能不同，FeatherScan能够根据服务的特点，准确清理相关日志文件，进一步消除渗透测试留下的痕迹。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALp47SYh55ialgpjTDaDeESH6BazOu8z1fK5WKvFn4WOK0HmcQXJj7xKCA/640?wx_fmt=png&from=appmsg "")  
## 0x05 使用示例展示  
### 基础扫描  
  
在获取FeatherScan工具后，首先需要赋予其可执行权限，使用命令“chmod +x FeatherScan”。然后，通过执行“./FeatherScan”命令即可启动基础扫描。基础扫描能够快速获取系统的一些基本信息，如当前用户、主机名、操作系统、内核版本等，为进一步的深入扫描提供基础数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpe8mkCUicUPPQEScEjEjp61sEZEFD6xiapnfxH5EId1joSYusCxraRn0g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpxbNpEZEmxd9NAKzmptUFfzI5XJVdlReoCt2BnJ9oT1a9GzdiaFOtQBQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpkZOKn2k7Y9ywjNsVpiaY0V8xcnFQC1bnXRP0ibsNgiar2Iv1o8u1ffQzg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpzwC0usmlpCQdgHNrvqCyDwzYvKbEPvQYRD1BfBRHNj8u0k31E8kic9g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALp3icxAiceQcegd4hMiaziaprA0xcOfnmK3Cy8dMPJPlbJzfSVvBFlJlAgFw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpn7yO72Vwf4QmSxaZBFc2HmF4lCoUicIzD0ZdWknGUgPXqfB0XhRWMvg/640?wx_fmt=png&from=appmsg "")  
  
### 启用深度检查+内网扫描  
  
当执行基础扫描后，工具会提示用户是否执行深入检查。用户输入“y”表示启用深入检查，此时工具会在基础扫描的基础上，对服务进行爆破以及对敏感文件进行深度扫描。接着，工具会询问是否执行内网渗透扫描，若输入“y”，则会开启主机发现、端口扫描、横向移动检测等内网渗透扫描功能。同时，工具还会询问是否启用隐身模式，若输入“n”，则以正常速度进行扫描。  
  
以下是详细的输出示例，展示了工具在扫描过程中获取的丰富信息：  

```
███████╗███████╗ █████╗ ████████╗██╗  ██╗███████╗██████╗
██╔════╝██╔════╝██╔══██╗╚══██╔══╝██║  ██║██╔════╝██╔══██╗
█████╗  █████╗  ███████║   ██║   ███████║█████╗  ██████╔╝
██╔══╝  ██╔══╝  ██╔══██║   ██║   ██╔══██║██╔══╝  ██╔══██╗
██║     ███████╗██║  ██║   ██║   ██║  ██║███████╗██║  ██║
╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

        高级Linux特权提升扫描工具
      泷羽Sec安全团队 | 白小羽 | v4.0

=================================================== 工具描述 =================================================
1、linux内网信息收集，全面收集操作系统/内核版本、环境变量、用户信息等关键数据
2、检测敏感文件权限、容器环境、服务配置等安全风险点,分析历史命令、环境变量、SSH配置等潜在攻击向量
3、智能主机发现（ARP/Ping/TCP混合扫描）,多协议服务爆破（SSH/MySQL/SMB等）,网络路由分析、DNS配置检测和代理设置审查
4、SUID/SGID文件扫描与危险程序识别,内核漏洞数据库匹配（脏牛、脏管道等）,Sudo规则审计与配置弱点分析
5、Docker逃逸路径检测和容器安全评估,隐身扫描模式（避免触发IDS）,自动化痕迹清除机制,敏感信息掩码保护

[-] 系统信息
[+] 当前用户: root
[+] 主机名: kali
[+] 操作系统: Kali GNU/Linux Rolling
[+] 内核版本: 6.12.25-amd64
[+] 扫描开始时间: Thu Jul 10 05:42:16 AM EDT 2025

[?] 是否执行深入检查?
  普通检查: 快速检测常见提权向量 (SUID, 可写文件, 内核漏洞等)
  深入检查: 包括普通检查 + 服务爆破 + 敏感文件深度扫描 [y/N]
y
[+] 深入检查已启用

[?] 是否执行内网渗透扫描?
  内网扫描: 主机发现、端口扫描、横向移动检测 [y/N]
n

################ 完整系统信息 ################

[-] 系统信息:
主机名: kali
操作系统: Kali GNU/Linux Rolling
内核版本: 6.12.25-amd64
系统架构: x86_64
运行时间: up 3 days, 22 hours, 52 minutes

[-] 用户信息:
当前用户: root
用户ID: uid=0(root) gid=0(root) groups=0(root)
特权用户: root
test
featheruser

```

## 0x06 使用建议强调  
### 授权测试  
  
FeatherScan是一款强大的工具，但必须仅在获得明确授权的环境中使用。未经授权对系统进行扫描和渗透测试可能会侵犯他人的合法权益，甚至触犯法律。因此，在使用该工具之前，务必确保已获得相关授权，以合法合规的方式进行安全测试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpE2kN7lLJTV68YbnvD2RC2rwbibD5qQBkcI4SJGZA3P5tzwJ67xo1iaGg/640?wx_fmt=png&from=appmsg "")  
### 深度扫描  
  
对于关键系统，建议启用深入检查模式。深入检查能够更全面地检测系统的安全风险，发现潜在的提权向量和安全漏洞。虽然深入检查可能会花费更多的时间和资源，但对于保障关键系统的安全性来说，这些投入是值得的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpQ2uw1VibjlbVEF8GHnLLU5RF6LQl09sib0a3BaaaibY5nUNV1Znd0vDBg/640?wx_fmt=png&from=appmsg "")  
### 痕迹管理  
  
扫描完成后，应及时使用内置的清理功能。安全痕迹管理功能可以帮助用户消除在目标系统上留下的操作痕迹，保护测试过程中的敏感信息不被泄露，同时也避免对目标系统造成不必要的影响。通过使用这些清理功能，能够确保渗透测试过程更加安全、隐蔽。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpWTgn00PXgOUOlRySwUpFFniaLe0PTV5lzVGrgQm4e5zL8wTT8q4Uk8Q/640?wx_fmt=png&from=appmsg "")  
### 字典定制  
  
根据目标环境定制pass.txt密码字典。不同的目标环境可能使用不同类型的密码，通过定制符合目标环境特点的密码字典，可以提高密码爆破的成功率。例如，如果目标系统是企业内部系统，可能需要考虑使用包含企业常用词汇、员工姓名等信息的密码字典；如果是个人系统，可能需要考虑使用常见的个人密码组合等。定制密码字典能够使工具更好地适应不同的目标环境，提高渗透测试的效率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bdvYume9OP9oj9ibycsaALpSwLR9vPTvBB5iaNCGQg6CxkNiasIaJjUNGA9bwMofBAoT0xDhDhQVs2w/640?wx_fmt=png&from=appmsg "")  
  
FeatherScan v4.0凭借其丰富的功能、独特的技术特点以及详细的使用指导，为Linux内网信息收集和特权提升检测提供了一个全面而高效的解决方案，无论是对于专业的安全研究人员还是渗透测试爱好者来说，都是一款值得深入研究和使用的工具。  
  
  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/4kCmTUe2v2bujwd3M0M1ICStsbhAHWtt0VVqCfFLOVnpmeNJ3R59doWtI0AmqLn4Qkic8aAS06l0pATjcYx10zw/640?wx_fmt=png "")  
  
  
