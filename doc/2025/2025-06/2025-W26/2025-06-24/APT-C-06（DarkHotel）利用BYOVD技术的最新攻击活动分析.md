> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyMjk4NzExMA==&mid=2247506352&idx=1&sn=c9c57e22e7b3300fe2c7d07520d1f339

#  APT-C-06（DarkHotel）利用BYOVD技术的最新攻击活动分析  
原创 高级威胁研究院  360威胁情报中心   2025-06-24 09:56  
  
**APT-C-06**  
  
    
**DarkHotel**  
  
APT-C-06（[#DarkHotel]()  
  
）在2025年2月通过钓鱼邮件投递恶意的证书安装包。此次攻击与该组织在2024年初的攻击非常类似：朝鲜语的安装包、年初短时间内大量投递、以涉朝贸易人员为主要目标。在攻击技战术方面，载荷中增加了大量检测、对抗杀毒软件的代码。  
#  一、攻击流程   
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTlE0qamL3557Kh6ZrLltshSuyWyk1mK9zxDTHP5aKviaThhw8EBgvnoA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
攻击者此次使用的诱饵文件为  
봉사기용전자증명서  
(2025).zip，翻译为中文是“服务用电子证书”（2024年攻击者使用的字体安装包）。压缩包内含cert.msi，执行该文件引发后续一系列恶意行为，最终导致恶意载荷在用户机器驻留。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTzUbSCicWpyaKicfslgK1ZAwicsehiaG5U4r0MLK0uNSVeLtyWsOOTicdibicQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
在msi文件的CustomAction表中定义了加载k1nqa.dll调用t12函数的操作。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTRW6nicYOic0BPDAia7gCIqVzeX8kP0tz7icpQ1UMkuJhb64IicZBZh0HoRg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
#  二、载荷分析   
## 1. cert.msi中的k1nqa.dll  
  
cert.msi在安装过程中调用k1nqa.dll的t12函数。程序在开始时通过进程和服务检查一系列杀毒软件的安装情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPT8qr1AEmozSVQ8XTImtcZGazYbX41RDyoPQO8Y0E5TxNmnW2IWd15aA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
创建计划任务\Microsoft\Windows\Shell\SH1执行Powershell代码。powershell的功能为下载下阶段载荷k1o，并执行。如果已有执行下阶段载荷的计划任务则移除自身。powershell代码中的下载链接由当前程序生成，后两个参数分别来源于当前系统的BuildNumber和杀软的安装情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPT5OS6ennoiaIQhsNUEEsezM2cJOoeXngzCzkG72CuqcCdkYIrYTmpicyQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
程序随后创建进程执行另一段powershell代码，用于展示一张图片，以欺骗用户程序在正常执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTtNGd0LrpASgm1TgP6xu7XZPbA2NGiagh0T20GMpu4pRN35OHHsPFAZQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
## 2. k1o中的k1nqa.dll  
  
下载的k1o文件仍然是一个msi文件，利用同样的方式加载内部的k1nqa.dll，并调用导出函数t1a1。由于样本的执行流程涉及多阶段多载荷，所有我们用一张图表示该样本的执行流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTcVZtchIb6m6gDUcsnCMjYIWLYc1etKib394T8yCrCHlOweTtickPHwmA/640?wx_fmt=png&from=appmsg "")  
  
![]( "")  
![]( "")  
  
2.1 初始化(t1a1)  
  
和之前攻击活动中出现的同类型样本一样利用32字节数据为flag定位配置数据，并解密。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTJ9hrcz8icveo4vibKbbmEomJjq0jugY9mkqRBYtvyUkzWQ2754zcSnfQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
程序通过MsiGetPropertyW获取OriginalDatabase和UIlevel属性。OriginalDatabase属性为当前msi文件的路径，用于后续判断程序是处于安装阶段还是驻留阶段。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTbfmQzwt1GKpN5bb2iaEhzicbpg6bibk4o9IDjdapOg6BLdIrSyXlEjsaw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
通过导出函数找到当前模块，获取当前模块路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTostEy2oc6GS5qwh4hjYaibsGYkaAgiaGMGbYAjBxusOalKOhJv6iaEPSQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
程序利用COM接口提升权限加载当前dll，调用导出函数a2，并传入之前获取的msi文件路径和两个url作为参数。随后遍历C:\Windows\Installer\目录寻找当前msi文件的副本，创建进程清除该文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPT1PwNX2Ujz9utn3ylTibejuUkEaDaut9OmIuQcVyvPsJ03Ph4bcSYTJQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
### 2.2 安装(a2)  
  
提权后的当前模块由dllhost.exe进程加载。程序重复和t1a1类似的操作：解密配置，从参数中获取两个url和msi文件路径，利用导出函数获取当前模块路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTA2sYzROSIQlWGqpUF8mckr8G0p2IVWQDwXy0pw1H1lghrzpMsJcrAg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
检查杀毒软件安装情况。每个杀软对应一个序号，最终形成一个序号列表表示当前机器的杀软安装情况。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTQs4tzsyZHeDClz6ibm7mjs37ErFfsH5gnG8L9dGrVzias1cnjxovgv0g/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
程序继续通过COM接口提升权限加载当前dll，调用导出函数a1。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTqyABI8WmYwtmMDxSvibiaLibGvlEvLwqw06TohcnmAedyS531EAuduhzA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
拷贝msi文件到C:\ProgramData\Microsoft\DRM\temp目录，创建计划任务\Microsoft\Windows\AppID\NvidiaTeleConv，执行msiexec.exe /i,C:\ProgramData\Microsoft\DRM\temp\systeminfo.msi,/qn。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTic7DnryqF7wre1jOGRNfz8JJLwoNOIDoW3gAIMHr4NwBiaH7q7HwlX2w/640?wx_fmt=png "")  
![]( "")  
![]( "")  
### 2.3 对抗杀软(a1)  
  
还是类似的初始化操作，解密配置。随后，程序利用类似操作从程序内部解密出一段shellcode。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTLwOjmdicDt4YIE9n6g4icQra3sVVic2dCsUQ2TIicLO5UdlO7Lkj1QMDXg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
模拟Power服务进程的Token创建进程dllhost.exe，并将前面解密的shellcode注入到该进程执行。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTzOibvkLHicK0FTdc7PJXibWia54tTSEBRNX7xyaiayAnZLBuKMRuKoMAiaLg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
Shellcode功能加载自身0xc0d偏移处的pe文件（md5:4f90ff96539cfd0a471165c0e6a957e2），实现后续的杀软对抗功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTOvaHt8Gu9HNhkz89YJZrNmNm3DvxuT0CrYK1Wd9I8piaWDCGticbaTiaA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
### 2.4 systeminfo.msi的t1a1  
  
由计划任务启动的systeminfo.msi同样会执行t1a1导出函数，程序通过判断当前msi文件的路径，进入远程命令执行的流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTlKtdIEmRhxIzKI0b6u8tp39pqu4ovKJlvJ8kPZ4AQJfcgH9kSRWhuA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
从远程地址请求数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTn6OWzrJVJu6k6hibWg61oVJCFp7bcX1gb76dicBK48PB9tbejMg6MicCw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
下载失败会向另一个地址报告状态。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTaZ6odquHxDicrrcdWR3lLSxnTxDU5JFiajmN7SLv9GkJNceHfWYl9d3w/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
解密数据，执行内含的shellcode。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTrUOVWqmd312UkIU8PajnODQsYFGzHMeTIYsvOXZ83c0ZCDsPJLeXgg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
暂时未下载到后续的shellcode。  
## 3. 对抗杀软  
### 3.1 loader  
  
当前载荷由前述的a1导出函数执行，用于加载后续的两个模块。载荷解密.sdata节区数据，节区内的的数据结构如下图所示。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPT9hGR3CE90SKMwfheLrjYQFwFddJQR5aYFLoB4Bt9zL7iasEebv7XU1w/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
不同的block action对应不同的数据处理动作：0代表将数据写入C:\ProgramData\Microsoft\Provisions\NvidiaConv.exe，并为之创建计划任务；1代表将数据写入EventStore.dll文件；2代表数据为shellcode，解密后注入Power服务进程执行；3代表将数据解密后写入C:\ProgramData\Microsoft\Setting\r0（0表示索引，随写入文件数量递增）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPT7cqyll7bw1Ms5qvLJXljCEibblyNM7wScd1bVkRJtvVumCoibcKNS8Bw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
当前样本文件含有两个block，block action都为2。两个shellcode使用了和前面shellcode一样的加载代码，加载自身包含的PE文件。两个载荷，一个载荷通过注册表禁用Windows Defender的诸多功能，另外一个用于关闭其它杀软进程。  
### 3.2 对抗Windows Defender  
  
移除WdFilter服务的驱动程序文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTWWCxzscTZFNS66GVicqtOYltQQ6v9LL9jdbqcJu07HRRaHa8UeE4yLA/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
将Microsoft Defender 对不同威胁严重级别的默认处理操作设为忽略。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTw6ftjgDydAa3hiboQqAEPEr0Xiaz9AJoJkJWmhjGP1HloTCjHxrUmbKw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
扰乱Microsoft Defender 的云保护服务功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTgyEpwsUt0iaRMufz6uDtwOXII4wBcXWdicE2eIIwQwcFuC3o0nn0b6vQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
禁用Microsoft Defender 的 核心服务（Core Service）的功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTfwQQ78AibngH2FnJibWbQaLHZ4DkqpKV2xKib9qbsOD0hAMkcwC5Ojfng/640?wx_fmt=png "")  
![]( "")  
![]( "")  
### 3.3 对抗其它杀软  
  
根据当前机器的情况释放不同sys文件，落地到C:\windows\temp\MpKslDrv.sys。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTMkfqUjFiaqBHmiatghc42U5UzonYQqaPTJsAT75RfUn1oyIokP47d0kg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
配置落地的sys文件为内核驱动程序，动态加载内核驱动程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTlcZZE2Q6GoLAib17XltiaLmqsnuCMMLbGay6B5O3Fqic94ibv60GOxcJ8g/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTeKyPw5zYcv5B0NDVyfHzmUJffE2ADa6eAteC66fJ6QRDSRWHVr6kxw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
循环判断当前运行进程列表中是否有存在于配置信息中提供的杀软进程列表中的进程，如果存在则利用之前加载的内核驱动程序关闭该进程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTGPTITHwswzE2apVxaFyAEGU7XibbGianCHx7J3uIk4m8erIePd0OGbiaw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
跳出上述循环后会移除之前创建的内核驱动程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTdoOZa0g5TrrK0A76SOMUxiby2OdR9MZ28lQVAUDqTuDnSf08VAcY5YQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
当前样本释放的两个sys文件md5为21e13f2cb269defeae5e1d09887d47bb和f53fa44c7b591a2be105344790543369，前者为杀软Zemana的驱动程序，后者为杀软Adlice的驱动程序。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTIZ4EgM0AAPsibHkaJONt08IEhhYb03QRDAYvTz1zNVibCA1mRRZ0gymw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
这里攻击者使用了BYOVD（Bring Your Own Vulnerable Driver）攻击：利用存在漏洞的驱动程序进行权限提升或绕过安全机制的攻击方式。在当前样本中，攻击者利用上述两个包含漏洞的驱动程序来关闭杀软进程。具体的实现方式是向两个驱动程序创建的设备handle发送特定的IO控制代码，再结合指定进程的pid，就可以关闭指定进程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPT2ShYF8Fquyhy2fVWiaSmfJiaLpynt2ygqRicNaEAOLZrePibicp4Z3SVKicQ/640?wx_fmt=png "")  
![]( "")  
![]( "")  
#  三、关联分析   
  
当前攻击活动与APT-C-06在2024年初发起的攻击行动在技战术方面存在多处相似。首先是载荷投递的方式，此前的攻击行动中也出现过利用安装包加载内部的恶意dll的执行方式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTrcNqmUMOfeNWoYicq3VWJDLZP4Nq3aYxFkks3MxibibRwccMBXEsllRRw/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
其次是载荷解密配置的方式，都是通过32位字节数据定位加密数据，并利用RC4+ RtlDecompressBuffer解密解压缩数据。利用同样解密算法解密的出来的配置文件格式相似。配置文件中出现的url的格式也相似。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6CNEHNicic4Ppux5mC5umm3rMA5LQAUMPTvOH1laibbvan4eBy9ibhxbtrvzIiaj6ue9icIFZvnxNj3ib9C35IfKP1RGg/640?wx_fmt=png "")  
![]( "")  
![]( "")  
  
##   
  
**总结**  
  
  
如此“重”的投入在杀软对抗上在APT-C-06之前的载荷中没有出现过。总体来说，该组织近些年技战术趋于“简单”：区别于之前的利用重量级的漏洞，转而采用灵活新颖的投递方式和攻击技术。在攻击目标方面，  
APT-C-06  
仍旧聚焦于涉朝的贸易人员，同一时期攻击的目标数量更多。  
  
  
**团队介绍**  
  
  
TEAM INTRODUCTION  
  
**360****高级威胁研究院**  
  
360高级威胁研究院是360数字安全集团的核心能力支持部门，由360资深安全专家组成，专注于高级威胁的发现、防御、处置和研究，曾在全球范围内率先捕获双杀、双星、噩梦公式等多起业界知名的0day在野攻击，独家披露多个国家级APT组织的高级行动，赢得业内外的广泛认可，为360保障国家网络安全提供有力支撑。  
  
