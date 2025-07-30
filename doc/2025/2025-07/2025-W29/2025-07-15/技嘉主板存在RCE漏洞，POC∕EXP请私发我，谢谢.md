> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIwMzU0ODczOA==&mid=2247486946&idx=3&sn=1c613f08674533cd087ddd5f7e44e002

#  技嘉主板存在RCE漏洞，POC/EXP请私发我，谢谢  
原创 黎多鱼  黎多鱼   2025-07-15 11:12  
  
## 1 事情概述  
  
安全研究人员发现技嘉 UEFI 固件中存在多个高危漏洞（CVE-2025-7026、CVE-2025-7027、CVE-2025-7028、CVE-2025-7029），这些漏洞位于系统管理模式（SMM）的 SMI 处理程序中，因对缓冲区验证不当，允许攻击者在操作系统加载前执行任意代码，禁用 Secure Boot 等 UEFI 安全机制，部署固件后门并获得系统永久性控制。  
  
这些漏洞最初在 AMI 固件中被发现并修复，但在技嘉固件中再次出现，影响数十款产品，攻击者需本地或远程管理员权限利用。  
  
**关键字：**  
技嘉固件、UEFI 漏洞、SMM（系统管理模式）、CVE-2025-7026 至 7029、安全绕过、固件后门、持久控制  
## 2 核心要点  
  
漏洞位于系统管理模式（SMM），这是一种高权限 CPU 模式（Ring-2 级别），运行于受保护的 SMRAM 中，仅通过系统管理中断（SMI）处理程序访问，漏洞因 SMI 处理程序对缓冲区验证不当导致。  
  
四个漏洞（CVE-2025-7026 至 7029）分别允许写入攻击者指定内存、向 SMRAM 写入任意内容、控制关键闪存操作，可被用于提升权限至 SMM 环境执行代码。  
  
攻击者需具备本地或远程管理员权限，利用漏洞可绕过操作系统级保护，禁用 Secure Boot、Intel BootGuard 等 UEFI 安全机制，部署传统端点工具无法检测的固件植入物。  
  
固件植入物具有持久性，即使操作系统重装、系统重启或处于恢复模式、睡眠状态，仍能存在  
，且可能影响虚拟机管理程序的内存隔离。  
  
漏洞最初在 AMI 固件中发现并通过私下披露修复，但在技嘉等 OEM 厂商的固件版本中再次出现，影响多达 240 款技嘉主板型号，涉及 Intel H110、B150 等芯片组。  
  
技嘉已发布固件更新以解决这些问题，建议用户访问其支持网站获取对应型号的更新，尤其是暴露于本地或远程管理访问的系统。  
  
这些漏洞利用难度较高，需高级知识，消费者风险相对较低，但关键基础设施环境需加强防护，限制对易受攻击系统的访问。  
## 3 MITRE 攻击技术  
  
<table><thead><tr><th style="color: rgb(255, 255, 255);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(0, 150, 136);height: auto;border-style: solid;border-width: 1px;border-color: rgb(0, 150, 136);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">技术编号</span></span></section></th><th style="color: rgb(255, 255, 255);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(0, 150, 136);height: auto;border-style: solid;border-width: 1px;border-color: rgb(0, 150, 136);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">描述</span></span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">T1068 - 权限提升</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">攻击者利用漏洞将权限提升至系统管理模式（Ring-2），绕过操作系统内核级保护，符合该技术中通过漏洞提升权限的特征。</span></span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">T1542 - 修改固件</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">漏洞允许攻击者在SMM中执行代码，部署固件后门或植入物，直接修改固件以获得持久控制，与该技术匹配。</span></span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">T1015 - 访问SMRAM</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">漏洞可使攻击者向系统管理内存（SMRAM）写入任意内容，破坏受保护内存区域，对应此技术中未经授权访问敏感内存区域的行为。</span></span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">T1070.004 - 禁用安全工具</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">攻击者利用漏洞禁用Secure Boot等UEFI安全机制，使传统端点保护工具失效，符合该子技术中禁用安全软件的特征。</span></span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">T1529 - 系统固件攻击</span></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgb(0, 150, 136);border-bottom-color: rgb(0, 150, 136);border-left-color: rgb(0, 150, 136);border-right-color: rgb(0, 150, 136);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;">针对UEFI固件中的SMM组件进行攻击，以实现对系统的持久控制和安全绕过，属于该技术范畴。</span></span></section></td></tr></tbody></table>  
## 4 威胁 IOC  
  
**涉及漏洞编号：**  
CVE-2025-7026、CVE-2025-7027、CVE-2025-7028、CVE-2025-7029****  
  
**受影响产品：**  
技嘉多个主板型号，包括使用 Intel H110、B150、X150/X170 等芯片组的消费类、游戏和 SMB 级主板（具体型号需参考技嘉官方公告）****  
  
**相关组件：**  
技嘉 UEFI 固件中的 SMM 组件（OverClockSmiHandler 模块）、AMI 提供的定制化固件  
  
  
欢迎转载，转载请注明出处@黎多鱼；  
  
消息来源：  
  
  
[1]https://www.securityweek.com/flaws-in-gigabyte-firmware-allow-security-bypass-backdoor-deployment/   
  
[2]https://securityonline.info/smm-vulnerabilities-in-gigabyte-uefi-firmware-expose-systems-to-stealthy-attacks/  
  
  
**·END·**  
  
关注我  
，每天了解一点国内外安全威胁情报，不走迷路。  
  
我是黎多鱼，聚焦安全威胁情报、行业资讯。  
  
  
  
  
  
