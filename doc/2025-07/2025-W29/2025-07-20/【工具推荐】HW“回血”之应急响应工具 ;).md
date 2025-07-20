> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1NTE2NzQ3NQ==&mid=2247487282&idx=1&sn=39dbecde057fe1e8d2edae6b8e23394d

#  【工具推荐】HW“回血”之应急响应工具 ;)  
FL_Clover  网络安全007   2025-07-20 01:00  
  
    HW开始已经一段时间了，挺多师傅在此期间需要进行应急响应进行“回血”报告的编写，这时候就会考虑到各种系统环境，各种工具在低版本系统和高版本系统之间来回切换的兼容性问题；这里推荐一款适合现阶段的应急响应工具，帮助大家在特殊时期进行“回血”；  
QDoctor是一款非传统意义上的ARK(Anti RootKit)工具。  
  
    文末附项目下载链接。  
  
一、工具介绍  
  
    QD既覆盖了传统ARK工具的功能，同时又兼顾了应急响应过程中的常见需求。使用此工具可以极大的提高应急处置的效率、快速定位目标环境中潜在的恶意项目所在位置。  
  
    QD的日志导出功能可以让普通用户轻松且全面的提取系统各种信息，导入功能则可以让专业人员可以全面掌握导出该日志主机的各项情况进而快速定位系统中的猫腻。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpAcdWZezDLOwicfQIfXdrqVDiauQ3OsENv4sFs4AoxMTo2Oqic6QayJB5uxa6Rl4RtK0IyeXsbpRH1g/640?wx_fmt=png&from=appmsg "")  
  
二、支持系统版本  

```
Windows 7 x86 x86_64
Windows 8 x86 x86_64
Windows 8.1 x86 x86_64
Windows 10 x86 x86_64
Windows 11 x86_64
Windows Server 2008 R2 x86_64
Windows Server 2012 x86_64
Windows Server 2012 R2 x86_64
Windows Server 2016 x86_64
Windows Server 2019 x86_64
Windows Server 2022 x86_64
```

  
三、功能介绍  
  
（1）特色功能  
- 一键导出各个标签页下的结构化数据(包括涉及文件的哈希值)。  
  
- 一键导入由其他机器导出的数据，方便排查问题。  
  
- 单文件同时支持X86、X86_64系统，系统支持较为全面。  
  
- 对部分有对抗性的样本具备穿透能力。  
  
（2）常规功能  
- 基本系统信息：系统MAC地址、系统版本等信息。  
  
- 自启动项目：注册表常见启动项、计划任务、服务、驱动、WMI。  
  
- 进程：查看进程、线程、模块、内存、句柄、内核回调； 暂停进程或线程执行、查杀进程或线程、卸载模块或内存、关闭句柄、签名验证、Hook扫描。  
  
- 内核：驱动模块、已卸载模块、系统回调函数、微过滤驱动、Sfilter过滤驱动、NDIS回调、SSDT表、ShadowSSDT表、DPC定时器、FSD驱动、对象信息、内核工作队列、设备栈、对象目录、键盘驱动、消息钩子。  
  
- 网络：查看各个进程的网络连接情况，支持IPv4&IPv6的TCP&UDP连接。  
  
- 系统补丁：查看当前系统安装的补丁状况。  
  
- 软件列表：查看当前系统安装的软件列表，内容等价于系统“添加删除程序”中显示的内容。  
  
- 系统日志：应用程序日志、安全日志、Setup日志、系统日志。  
  
- 文件系统：简易文件管理器，可以查看系统各个盘（包括映射到本地的网络位置）下的内容以及强制删除文件。  
  
- 其他：环境变量、共享文件夹信息。  
  
四、部分功能截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpAcdWZezDLOwicfQIfXdrqVnpYF6pfAeZZyXfVd3EDgRmUXicVthxWicMQpeSALMKVb6QFEjmfXAibxA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpAcdWZezDLOwicfQIfXdrqViaicDSW4Yn2IQhJEDD6Lkz407QDf1wKrcYI8df7gR7UKXJAdTwsVs5cg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpAcdWZezDLOwicfQIfXdrqVAkCDAia6MdrXa4xLdoicfTY7p2P64XwlZxbPic2dOk6YHxPTEQOxCic7SA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2txKvJB0ibDpAcdWZezDLOwicfQIfXdrqVsOn5Eib5K84IJJaeVlWHgyu8bQg0bNG0mn6UztoYgg0JTKAYOGt523g/640?wx_fmt=png&from=appmsg "")  
  
五、工具获取  
  
在本公众号后台回复【  
QD  
】即可获取项目地址&下载链接！  
  
<table><tbody><tr><td data-colwidth="576"><p data-pm-slice="0 0 []" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;font-size: 17px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;color: red;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">免责声明：</span></span></strong></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;color: rgba(0, 0, 0, 0.9);font-size: 17px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"> </span></span><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">本文章仅做网络安全技术研究使用！另利用网络安全007公众号所提供的所有信息进行违法犯罪或造成任何后果及损失，均由</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">使用者自身承担负责</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">，与网络安全007公众号</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">无任何关系</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">，也不为其负任何责任，</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">请各位自重！</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">公众号发表的一切文章如有侵权烦请私信联系告知，我们会立即删除并对您表达最诚挚的歉意！感谢您的理解！</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">让我们一起为我国网络安全事业尽一份自己的绵薄之力！</span></span></strong></span></p></td></tr></tbody></table>  
**●****推荐阅读●**  
  
****  
**应急响应系列**  
  
**未授权访问漏洞系列**  
  
**Nessus漏扫神器之攻防两用**  
  
**红队如何在攻防演练中一夜暴富？**  
# 浅谈Nacos漏洞之超管权限后续利用  
  
****  
**超级弱口令工具+超级字典，攻防必备！**  
  
**记某APP服务端渗透测试实战GetShell**  
  
**日常实战渗透小技巧，掌握就无需担心漏洞产出为零！**  
  
**实战|某网站未授权访问=》数据库权限=》服务器权限**  
  
**全方位揭秘：50多种横向渗透提权终极技巧，一篇文章彻底掌握！**  
  
写作不易，分享快乐  
  
期待你的 **分享**  
●**点赞●在看●关注●收藏**  
  
