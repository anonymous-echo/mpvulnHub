#  【勒索防护】Mallox新变种再度来袭，正利用产品漏洞对国内企业实施攻击   
深盾终端实验室  深信服千里目安全技术中心   2025-05-13 10:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xlmiaBFUAZHb6txERZ1Hw4Q6mbWvwNbOTQuT8Nkh55FW1HMCA6rzdj2x8jqCr3mXmPYy7qAAwxwTQ/640?wx_fmt=gif&from=appmsg "")  
  
**恶意文件名称：**  
  
Mallox  
**威胁类型：**  
  
勒索病毒  
  
**简单描述：**  
  
Mallox勒索病毒首次出现于2021年10月，采用RaaS（勒索软件即服务）模式运营，将企业作为其攻击目标，利用产品漏洞阶段性实施大范围攻击。此次新变种于2024年10月底开始出现，其加密后缀包括 .weaxor、.wxx、.wxr、.rox 等。  
目前，【深信服统一端点安全管理系统aES】已支持查杀拦截此病毒。  
  
  
  
  
**事件分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wFucx34I7IloyMR46zIoPFp1o8QFefAtTMe6J0vEwMNrUh7JlEMwPL1FC2ibQrpml3yTcKiamAT97g/640?wx_fmt=gif "")  
  
**攻击溯源分析**  
  
近期，深信服应急响应团队和深盾终端安全实验室接到多起Mallox攻击溯源请求，  
通过整合终端安全软件日志、用户行为日志、进程监控数据等多种日志源，结合该勒索软件家族的攻击特征及情报信息，利用AI技术进行综合分析，最终构建攻击者行为特征画像和受害者影响范围画像。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensa601NGD7KKtc7T5F1Cq5S19AnibmicUqAvppZYWgFbVJc6BhAu2xF5iaAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensaXyJdJvjqMTsCb3QEIvy2ib99D5IbfdVQuU6gGIIvGKUv9VsuwRYl99Q/640?wx_fmt=png&from=appmsg "")  
  
发现该组织分工明确（涵盖信息收集、漏洞挖掘、批量攻击等专职团队），通过利用国内厂商0day/nday漏洞分阶段发起定向/批量渗透攻击，并形成日均活跃、周末及节假日休眠（如五一假期休眠将近一周多）的规律。  
  
此外该勒索组织利用数十家企业的OA系统、财务管理系统及定制化平台中的SQL注入、文件上传漏洞、远程代码执行漏洞（RCE） 获取初始访问权限；随后通过反序列化、webshell等多种方式执行PowerShell命令，远程下载云端shellcode以实现对主机的控制。攻击者利用BYOVD技术强制结束安全软件进程，进一步入侵MS-SQL管理员账户（SA），并额外安装AnyDesk远程程序，以绕过安全措施并提升操作便捷性，最后实施最终勒索动作。目前暂未发现该攻击链中存在横向移动痕迹。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensalvvN8Nd5GRb2F7L6vXjUvfcKJfmKvibUqrLAkjKkhkIlRjd2Jjf2FGw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wFucx34I7IloyMR46zIoPFp1o8QFefAtTMe6J0vEwMNrUh7JlEMwPL1FC2ibQrpml3yTcKiamAT97g/640?wx_fmt=gif "")  
  
**恶意文件分析**  
  
该恶意软件首先会调用GetUserDefaultLanguageID检查当前计算机的语言设置，并在特定语言环境（如俄语、哈萨克语、白俄罗斯语、乌克兰语和鞑靼语）下直接退出程序，从而避免加密这五种语言环境下的文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensaGtpoApegEokTlAmV1AR0HkDibpiaBrfUpXhBnhEXEEBIGd2tqQJ2wqPg/640?wx_fmt=png&from=appmsg "")  
  
  
通过加载 PowrProf.dll 库并调用 PowerSetActiveScheme 函数，Mallox将系统的电源模式设置为高性能，以提高系统性能和响应速度。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensahPl3rib79LvGrtnpK14BUgfdIVXFANSwc7Bia7WmWLySTRuI3OG06GYQ/640?wx_fmt=png&from=appmsg "")  
  
  
获取当前进程的访问令牌并调整其权限，获取更高的系统控制权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensaOYw3XIR3PI1uE2ICfolkibCuepuzQlcVUlwcTawPc8LX5VG8NjDeHMw/640?wx_fmt=png&from=appmsg "")  
  
  
删除与反勒索工具Raccine相关的注册表项，以防止这些工具干预勒索软件的运行。Raccine是一个由Florian开源的反勒索软件，利用注册表项Image File Execution Options的监控机制，对勒索软件常用的系统程序进行监控，如 vssadmin.exe、bcdedit.exe、wmic.exe、powershell.exe 等。触发监控程序后，Raccine会寻找其可疑父进程进行终止。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensa3WaSzTyJyMIdCeSVydJNibte66w8bD0dA54JXMIholqkuQt9qkoa6KA/640?wx_fmt=png&from=appmsg "")  
  
  
删除  
卷影副本，防止通过卷影恢复数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensaX3ApMeeJJtjMkgI4zibdMLIdvlhnlTP4u6Knic9urgTiatvXIF5dGJJfg/640?wx_fmt=png&from=appmsg "")  
  
  
从A到Z遍历磁盘驱动器，根据位掩码筛选目标驱动器，计算已使用的存储空间。这一过程可能用于评估可加密的存储空间。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensakjaAVrvalZtTpKDYgHS2rKDSiaRqNOC8bibWQQ5Jj5SHzrSpaCkoo6mA/640?wx_fmt=png&from=appmsg "")  
  
  
遍历系统中的所有卷，并提取每个卷的驱动器字母和挂载文件夹路径，以获取文件系统的结构，便于后续的文件操作。如果发现未挂载的卷，恶意软件会调用 SetVolumeMountPointW 函数将其挂载，以便访问和操作这些卷中的文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensaV4ozYoCvyK8Gtbdjne2tHsm1ugh1rYURRr3shZDvnGOW3ibecb6bXsA/640?wx_fmt=png&from=appmsg "")  
  
  
调用ClearEventLogW清除了185种日志。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensaHC3H7cUK1GclU5ibBkibemEh4zbfdd1J2eSKxbPou4EK4vPB240D4ZoA/640?wx_fmt=png&from=appmsg "")  
  
  
通过访问 http://api.ipify.org获取本机外网IP。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensahSqIar1Exuj1HFia17IRQ17Wxx8cUXWF3MBjmWGPqQCarjPYw9GJZmw/640?wx_fmt=png&from=appmsg "")  
  
  
在加密文件之前，勒索软件会收集以下系统信息：系统版本、哈希值、目标密钥、内外部IP地址、主机名、用户名、操作系统信息、语言环境、操作系统架构、CPU、内存容量、数据库卷、备份卷、虚拟卷以及已用磁盘容量等。这些信息会被发送至C&C服务器http[:]//193.143.1.139/Ujdu8jjooue/biweax.php（已失效）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensaZ52rQ9mNYBF0SYkATMqU6wWY9QCvcNzWDp6RunAmjUHb05fM61WZjw/640?wx_fmt=png&from=appmsg "")  
  
  
RECOVERY INFO.txt赎金文件内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensa42oicNcRGP283svofysvGP6G7Vibiaq2wHWdM5AnickAa5UfO7lEgMj7KQ/640?wx_fmt=png&from=appmsg "")  
  
  
被加密后的文件系统  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensalYibdibJBzquGq2oAUm7LCooNA8GpAFkOCWKlPrQqn1Pk2s46fibSkyag/640?wx_fmt=png&from=appmsg "")  
  
  
  
**IOCs**  
  
  
<table><tbody><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-style: solid;border-color: windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">0ca38cddd100f677a208414bef656ae0</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-style: solid;border-color: windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">Mallox </span></span></font></span><span style=""><span leaf=""><span textstyle="" style="font-size: 15px;">MD5</span></span></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">4c74caa9c0eeb2c7637da9bbde9535d7</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">Mallox </span></span></font></span><span style=""><span leaf=""><span textstyle="" style="font-size: 15px;">MD5</span></span></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">7286f8e0a7c344462186f35d46b6ae71</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">Mallox </span></span></font></span><span style=""><span leaf=""><span textstyle="" style="font-size: 15px;">MD5</span></span></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">a087e994db776a0c657e45d315851186</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">Mallox </span></span></font></span><span style=""><span leaf=""><span textstyle="" style="font-size: 15px;">MD5</span></span></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">a74ee50d2f91f77f010ecb154aa6b30b</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">Mallox </span></span></font></span><span style=""><span leaf=""><span textstyle="" style="font-size: 15px;">MD5</span></span></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">http[:]//193.143.1.139/Ujdu8jjooue/biweax.php</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">C&amp;C</span></span></font></span><span style=""><o:p></o:p></span></p></td></tr><tr style="height:30.0000pt;"><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">.386,.adv,.ani,.bat,.bin,.cab,.cmd,.com,.cp,.cur,.deskthemepack,.diagcfg,.diagpkg,.diangcab,.drv,.hlp,.hta,.ic,.icns,.ico,.ics,.idx,.key,.lock,.mod,.mpa,.msc,.msi,.msp,.msstyles,.msu,.nls,.nomedia,.ocx,.prf,.rom,.rox,.rtp,.scr,.shs,.sp,.sys,.theme,.themepack,.wex,.wpx</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="仿宋_GB2312"><span leaf=""><span textstyle="" style="font-size: 15px;">避免加密的文件后缀</span></span></font></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">Anydesk.exe,Anydesk.msi,AnyDeskMSI.exe,autorun.inf,boot.ini,bootfont.bin,bootsect.bak,debugLog.txt,desktop.ini,iconcache.db,ntldr,ntuser.dat,ntuser.dat.log,ntuser.ini,stepdata.txt,thumbs.db,wex.txt,windows.old,wxr.txt</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="仿宋_GB2312"><span leaf=""><span textstyle="" style="font-size: 15px;">避免加密的文件名</span></span></font></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">$windows.~bt,$windows.~ws,appdata,application data,Assemblies,boot,Common Files,Core Runtime,google,intel,Internet Explorer,Microsoft Analysis Services,Microsoft ASP.NET,Microsoft Help Viewer,Microsoft MPI,Microsoft Security Client,Microsoft.NET,mozilla,msocache,Package,Package Store,perflogs,programdata,Reference,Store,system volume information,tor browser,Windows,Windows Defender,Windows Kits,Windows Mail,Windows Microsoft.NET,Windows NT,Windows Photo Viewer,Windows Portable Devices,Windows Sidebar,windows.old,WindowsPowerShell</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="仿宋_GB2312"><span leaf=""><span textstyle="" style="font-size: 15px;">避免加密的文件目录</span></span></font></span><span style=""><o:p></o:p></span></p></td></tr><tr><td data-colwidth="394" width="394" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="Times New Roman"><span leaf=""><span textstyle="" style="font-size: 15px;">Application,HardwareEvents,Internet Explorer,Key Management Service,Microsoft-WindowsPhone-Connectivity-WiFiConnSvc-Channel,Microsoft-WindowsPhone-LocationServiceProvider/Debug,Microsoft-WindowsPhone-Net-Cellcore-CellManager/Debug,Microsoft-WindowsPhone-Net-Cellcore-CellularAPI/Debug,Microsoft-Windows-TunnelDriver,Microsoft-Windows-UserPnp/Performance,Microsoft-Windows-UserPnp/SchedulerOperations,Microsoft-Windows-UserSettingsBackup-BackupUnitProcessor/Operational,Microsoft-Windows-UserSettingsBackup-Orchestrator/Operational,Microsoft-Windows-UxInit/Diagnostic,Microsoft-Windows-UxTheme/Diagnostic,Microsoft-Windows-VAN/Diagnostic,Microsoft-Windows-VDRVROOT/Operational,Microsoft-Windows-VerifyHardwareSecurity/Admin,Microsoft-Windows-VerifyHardwareSecurity/Operational,Microsoft-Windows-VHDMP-Analytic,Microsoft-Windows-VHDMP-Operational,Microsoft-Windows-VIRTDISK-Analytic,Microsoft-Windows-Volume/Diagnostic,Microsoft-Windows-VolumeControl/Performance,Microsoft-Windows-VolumeSnapshot-Driver/Analytic,Microsoft-Windows-VolumeSnapshot-Driver/Operational,Microsoft-Windows-VPN/Operational,Microsoft-Windows-VPN-Client/Operational,Microsoft-Windows-VWiFi/Diagnostic,Microsoft-Windows-WABSyncProvider/Analytic,Microsoft-Windows-Wcmsvc/Diagnostic,Microsoft-Windows-Wcmsvc/Operational,Microsoft-Windows-WCN-Config-Registrar/Diagnostic,Microsoft-Windows-WCNWiz/Analytic,Microsoft-Windows-WDAG-PolicyEvaluator-CSP/Operational,Microsoft-Windows-WDAG-PolicyEvaluator-GP/Operational,Microsoft-Windows-WebAuth/Operational,Microsoft-Windows-WebAuthN/Operational,Microsoft-Windows-WebcamProvider/Analytic,Microsoft-Windows-WebIO/Diagnostic,Microsoft-Windows-WebIO-NDF/Diagnostic,Microsoft-Windows-WebPlatStorage-Server,Microsoft-Windows-WebServices/Tracing,Microsoft-Windows-Websocket-Protocol-Component/Tracing,Microsoft-Windows-WEPHOSTSVC/Operational,Microsoft-Windows-WER-PayloadHealth/Operational,Microsoft-Windows-WFP/Analytic,Microsoft-Windows-WFP/Operational,Microsoft-Windows-WiFiDisplay/Analytic,Microsoft-Windows-Win32k/Concurrency,Microsoft-Windows-Win32k/Contention,Microsoft-Windows-Win32k/Messages,Microsoft-Windows-Win32k/Operational,Microsoft-Windows-Win32k/Power,Microsoft-Windows-Win32k/Render,Microsoft-Windows-Win32k/Tracing,Microsoft-Windows-Win32k/UIPI,Microsoft-Windows-Windeploy/Analytic ,Microsoft-Windows-Windows Defender/Operational,Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurity,Microsoft-Windows-Windows Firewall With Advanced Security/ConnectionSecurityVerbose,Microsoft-Windows-Windows Firewall With Advanced Security/Firewall,Microsoft-Windows-Windows Firewall With Advanced Security/FirewallDiagnostic,Microsoft-Windows-Windows Firewall With Advanced Security/FirewallVerbose,Microsoft-Windows-WindowsBackup/ActionCenter,Microsoft-Windows-WindowsColorSystem/Debug,Microsoft-Windows-WindowsColorSystem/Operational,Microsoft-Windows-WindowsSystemAssessmentTool/Operational,Microsoft-Windows-WindowsSystemAssessmentTool/Tracing¬dXqZJ0,Microsoft-Windows-WindowsUIImmersive/Diagnostic,Microsoft-Windows-WindowsUIImmersive/Operational,Microsoft-Windows-WindowsUpdateClient/Analytic,Microsoft-Windows-WindowsUpdateClient/Operational,Microsoft-Windows-WinHttp/Diagnostic,Microsoft-Windows-WinHttp/Operational,Microsoft-Windows-WinHTTP-NDF/Diagnostic,Microsoft-Windows-WinHttp-Pca,Microsoft-Windows-WinINet/Analytic,Microsoft-Windows-WinINet/Operational,Microsoft-Windows-WinINet/Pca,Microsoft-Windows-WinINet/UsageLog,Microsoft-Windows-WinINet/WebSocket,Microsoft-Windows-WinINet-Capture/Analytic,Microsoft-Windows-WinINet-Config/ProxyConfigChanged,Microsoft-Windows-Wininit/Diagnostic,Microsoft-Windows-Winlogon/Diagnostic,Microsoft-Windows-Winlogon/Operational,Microsoft-Windows-WinMDE/MDE,Microsoft-Windows-WinML/Analytic,Microsoft-Windows-WinNat/Oper,Microsoft-Windows-WinNat/Trace dX}WJ0,Microsoft-Windows-WinRM/Analytic,Microsoft-Windows-WinRM/Debug,Microsoft-Windows-WinRM/Operational,Microsoft-Windows-Winsock-AFD/Operational,Microsoft-Windows-Winsock-NameResolution/Operational,Microsoft-Windows-Winsock-WS2HELP/Operational,Microsoft-Windows-Winsrv/Analytic,Microsoft-Windows-WinURLMon/Analytic,Microsoft-Windows-Wired-AutoConfig/Diagnostic,Microsoft-Windows-Wired-AutoConfig/Operational,Microsoft-Windows-WLAN-Autoconfig/Diagnostic,Microsoft-Windows-WLAN-AutoConfig/Operational,Microsoft-Windows-WLANConnectionFlow/Diagnostic,Microsoft-Windows-WlanDlg/Analytic,Microsoft-Windows-WLAN-Driver/Analytic,Microsoft-Windows-WLAN-MediaManager/Diagnostic,Microsoft-Windows-wmbclass/Analytic,Microsoft-Windows-wmbclass/Trace,Microsoft-Windows-WMI-Activity/Debug,Microsoft-Windows-WMI-Activity/Operational,Microsoft-Windows-WMI-Activity/Trace,Microsoft-Windows-WMPDMCUI/Diagnostic,Microsoft-Windows-WMPNSS-PublicAPI/Diagnostic,Microsoft-Windows-WMPNSS-Service/Diagnostic,Microsoft-Windows-WMPNSS-Service/Operational,Microsoft-Windows-WMPNSSUI/DiagnosticNavigator,Microsoft-Windows-Wordpad/Admin,Microsoft-Windows-Wordpad/Debug,Microsoft-Windows-Wordpad/Diagnostic,Microsoft-Windows-WorkFolders/Analytic,Microsoft-Windows-WorkFolders/Debug,Microsoft-Windows-WorkFolders/Operational,Microsoft-Windows-WorkFolders/WHC,Microsoft-Windows-Workplace Join/Admin,Microsoft-Windows-WPD-API/Analytic,Microsoft-Windows-WPD-ClassInstaller/Analytic,Microsoft-Windows-WPD-ClassInstaller/Operational,Microsoft-Windows-WPD-CompositeClassDriver/Analytic,Microsoft-Windows-WPD-CompositeClassDriver/Operational,Microsoft-Windows-WPD-MTPBT/Analytic,Microsoft-Windows-WPD-MTPClassDriver/Analytic,Microsoft-Windows-WPD-MTPClassDriver/Operational,Microsoft-Windows-WPD-MTPIP/Analytic,Microsoft-Windows-WPD-MTPUS/Analytic,Microsoft-Windows-WSC-SRV/Diagnostic,Microsoft-Windows-WUSA/Debug,Microsoft-Windows-WWAN-CFE/Diagnostic ,Microsoft-Windows-WWAN-MediaManager/Diagnostic,Microsoft-Windows-WWAN-MM-Events/Diagnostic,Microsoft-Windows-WWAN-NDISUIO-EVENTS/Diagnostic,Microsoft-Windows-WWAN-SVC-Events/Diagnostic,Microsoft-Windows-WWAN-SVC-Events/OperationalOfficeChannel,Microsoft-Windows-XAML/Default,Microsoft-Windows-XAML-Diagnostics/Default,Microsoft-Windows-XAudio2/Debug,Microsoft-Windows-XAudio2/Performance,Network Isolation Operational,NIS-Driver-WFP/Diagnostic,OAlerts,OfficeDebugChannel,OpenSSH/Admin,OpenSSH/Debug,OpenSSH/Operational,OSK_SoftKeyboard_Channel,Physical_Keyboard_Manager_Channe,Physical_Keyboard_Manager_Channel,PlayReadyPerformanceChannel,RTWorkQueueTheading,Schannel Security Package,Security,Setup,SmbWmiAnalytic,SMSApi,System,SystemEventsBroker,TabletPC_InputPanel_Channel,TabletPC_InputPanel_Channel/IHM,TimeBroker,Uac/Debug,UIManager_Channel,Windows Networking Vpn Plugin Platform/Operational,Windows Networking Vpn Plugin Platform/OperationalVerbose,Windows PowerShell,WINDOWS_KS_CHANNEL,WINDOWS_MFH264Enc_CHANNEL,WINDOWS_MP4SDECD_CHANNEL,WINDOWS_MSMPEG2ADEC_CHANNE,WINDOWS_MSMPEG2VDEC_CHANNEL,WINDOWS_VC1ENC_CHANNEL,WINDOWS_WMPHOTO_CHANNEL,WINDOWS_wmvdecod_CHANNEL,WMPSetup,WMPSyncEngine,WordChannel</span></span></font></span><span style=""><o:p></o:p></span></p></td><td data-colwidth="127" width="127" valign="top" style="padding: 0pt 5.4pt;border-left: 1pt solid windowtext;border-right: 1pt solid windowtext;border-top: none;border-bottom: 1pt solid windowtext;"><p style="text-align:justify;word-break:break-all;text-autospace:ideograph-numeric;mso-pagination:widow-orphan;text-justify:inter-ideograph;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style=""><font face="仿宋_GB2312"><span leaf=""><span textstyle="" style="font-size: 15px;">清除的日志</span></span></font></span><span style=""><o:p></o:p></span></p></td></tr></tbody></table>  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5xlmiaBFUAZHb6txERZ1Hw4Qwe9XgMczF63ob3sKSz1kP7YeZTjCiau7oyPe3lHnHt69thpRU5Aa6YQ/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
****  
**【深信服统一端点安全管理系统aES】**  
已支持查杀拦截此次事件使用的病毒文件，aES全新上线“动静态双AI引擎”，静态AI能够在未知勒索载荷落地阶段进行拦截，动态AI则能够在勒索载荷执行阶段进行防御，通过动静态AI双保险机制可以更好地遏制勒索蔓延。不更新也能防护，但建议更新最新版本，取得更好防护效果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yvvkgUVovpm67ZQicTyensalzEGMvPViciaLx4okUJXJ1THv4U49uWUB6pcibPcVa8dgENUnqkm1aDhQ/640?wx_fmt=png&from=appmsg "")  
  
****  
**【深信服安全托管服务MSS】**  
  
以保障用户网络安全“持续有效”为目标，通过将用户安全设备接入安全运营中心，依托于XDR安全能力平台和MSSP安全服务平台实现有效协同的“人机共智”模式，围绕资产、脆弱性、威胁、事件四个要素为用户提供7*24H的安全运营服务，快速扩展持续有效的安全运营能力，保障可承诺的风险管控效果。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5zvcIHbwGGYKbqDVYsVKzNNia1jYtHf49C7133AlDXAgex2W4lFvpia56tjQQDkiauNBrl08YbxqG01A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
