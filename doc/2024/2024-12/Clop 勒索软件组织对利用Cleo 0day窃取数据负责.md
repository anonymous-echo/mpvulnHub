#  Clop 勒索软件组织对利用Cleo 0day窃取数据负责   
会杀毒的单反狗  军哥网络安全读报   2024-12-16 01:00  
  
**导****读**  
  
  
  
  
Clop 勒索软件团伙向 BleepingComputer 证实，他们是最近 Cleo 数据盗窃攻击的幕后黑手，利用零日漏洞侵入公司网络并窃取数据。  
  
  
Cleo 是托管文件传输平台 Cleo Harmony、VLTrader 和 LexiCom 的开发商，公司使用这些平台在业务合作伙伴和客户之间安全地交换文件。  
  
  
10 月份，Cleo 修复了编号为 CVE-2024-50623 的漏洞，该漏洞允许不受限制的文件上传和下载，从而导致远程代码执行。  
  
  
网络安全公司 Huntress 上周发现，这个补丁并不完整，威胁组织正在积极利用绕过方法进行数据盗窃攻击。  
  
  
在利用此漏洞时，威胁组织上传了一个 JAVA 后门，使攻击者可以窃取数据、执行命令并进一步访问受感染的网络。  
  
  
周五，CISA 确认Cleo Harmony、VLTrader 和 LexiCom 文件传输软件中的关键安全漏洞 。  
  
  
CVE-2024-50623 已被利用于勒索软件攻击。然而，Cleo 从未公开披露他们在 10 月份试图修复的原始漏洞被利用。  
  
### Clop声称对Cleo数据窃取攻击负责  
###   
  
此前人们认为 Cleo 攻击是由一个名为 Termite 的新勒索软件团伙发起的。然而，Cleo 数据窃取攻击与 Clop 勒索软件团伙之前发起的攻击更为接近。  
  
  
周二，勒索软件团伙证实，他们是最近利用 Huntress 检测到的 Cleo 漏洞以及利用 10 月份修复的原始 CVE-2024-50623 漏洞的幕后黑手。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaGqmr57UcpJXNBapG96LYEL7aJekdqcG8XVVT0aNOhUwBJlDhzYS3csmOjNnicTPSNcGBDAKRqwyew/640?wx_fmt=png&from=appmsg "")  
  
CL0P^_-LEAKS 勒索网站上的消息，来源：BleepingComputer  
  
  
BleepingComputer 向 Clop 询问攻击何时开始、有多少公司受到影响以及 Clop 是否与 Termite 勒索软件团伙有关联，没有收到这些问题的答复。  
  
### 专注于利用文件传输平台  
###   
  
Clop 勒索软件团伙（又名 TA505 和 Cl0p）于 2019 年 3 月成立，当时它首次使用CryptoMix 勒索软件的变种开始针对企业进行攻击 。  
  
  
与其他勒索软件团伙一样，Clop 会入侵企业网络，并在窃取数据和文件的同时慢慢向系统内部扩散。窃取到所有有价值的东西后，他们会在网络上部署勒索软件来加密设备。  
  
  
勒索软件团伙偏爱针对安全文件传输平台中的未知漏洞进行数据盗窃攻击，最严重的此类攻击是  
2023  
年利用MOVEit Transfer 平台的一系列  
0day  
漏洞攻击，事件中有 2,773 个组织的数据被盗。  
  
  
目前，尚不清楚有多少公司受到 Cleo 数据盗窃攻击的影响。  
  
  
新闻链接：  
  
https://www.bleepingcomputer.com/news/security/clop-ransomware-claims-responsibility-for-cleo-data-theft-attacks/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
