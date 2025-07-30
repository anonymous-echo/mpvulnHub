#  Android Zygote 注入漏洞曝光：攻击者可借此执行代码获提权   
山卡拉  嘶吼专业版   2025-03-31 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
在 Android 操作系统中，研究人员发现了一个编号为 CVE-2024-31317 的严重漏洞。该漏洞允许攻击者借助 Zygote 进程，在整个系统范围内执行代码并提升权限。此缺陷影响运行 Android 11 或更早版本的设备，在 Android 生态系统中暴露出一个不容忽视的安全隐患。  
# 背景和漏洞详细信息  
  
Zygote 进程作为 Android 的基础组件，承担着生成新的应用程序和系统级进程的关键任务。它以系统权限运行，这使其成为了企图提升访问权限的攻击者的重点目标。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o28VbuPccwZagxQYf3H4PYSynqMyyibic4VOoyPc1cvgibCcSsTYv7o9x6Brek9FKAfsBIu6A4vDNmSrA/640?wx_fmt=jpeg&from=appmsg "")  
  
Android 启动过程的高级概述  
  
该漏洞的根源在于系统服务器处理 “hidden_api_blacklist_exemptions” 设置的方式。这种处理方式存在缺陷，导致某些应用程序能够绕过 Android 的隐藏 API 限制。具体而言，系统服务器在向 Zygote 传递此设置时，未能正确转义换行符，这一疏忽给攻击者创造了可乘之机，他们能够向 Zygote 进程注入任意命令。  
# 通过 ADB Shell 进行利用  
  
攻击者可借助 Android Debug Bridge（ADB）Shell 来利用这一漏洞。ADB Shell 具备 “WRITE_SECURE_SETTINGS” 权限，能够修改 “hidden_api_blacklist_exemptions” 设置。攻击者通过向该设置注入恶意命令，就能够以系统范围的权限执行任意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o28VbuPccwZagxQYf3H4PYSyyGwSiaKj4CCfWcpHliaoXiaOCdznz1PMRBAM0ibxZylTLpw1YcSMocnc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
Android 系统服务器源代码中存在漏洞的部分。  
  
概念验证漏洞展示了攻击者如何通过注入有效载荷来生成具有提升权限的新进程，从而将权限从普通 shell 用户提升至系统用户。据研究人员介绍，这一进程可被配置为执行诸如启动持久 shell 等命令，使得攻击者能够持续控制设备。  
  
利用此漏洞可能引发严重后果。若漏洞未得到妥善清除，极有可能导致设备陷入启动循环。  
# 风险缓解措施  
  
为降低这些风险，用户可以通过 ADB Shell 删除被修改的 “hidden_api_blacklist_exemptions” 设置，然后重启设备，以此恢复 Zygote 的正常运行。不过，这一操作也会清除任何已注入的有效载荷，意味着攻击者若想重新获取提升的访问权限，需要再次重复利用该漏洞的过程。  
  
此漏洞的发现，凸显了保护 Android 核心进程的重要性，同时也强调了及时进行漏洞修补，以防范此类安全隐患的紧迫性。  
  
参考及来源：  
https://gbhackers.com/android-zygote-injection-flaw/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28VbuPccwZagxQYf3H4PYSyCdkdwH8dcQs8kYPhQDEgTAhn8FsRn1KOgCU5ObevoPyJX3T81OXxLA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o28VbuPccwZagxQYf3H4PYSyhOxibIic3XcB4ewqaMhhzwict7ibroWC3oIXXtBmgYkztexnVozum0D8OQ/640?wx_fmt=png&from=appmsg "")  
  
  
