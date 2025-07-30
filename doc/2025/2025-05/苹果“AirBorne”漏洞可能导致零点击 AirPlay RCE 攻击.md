#  苹果“AirBorne”漏洞可能导致零点击 AirPlay RCE 攻击   
胡金鱼  嘶吼专业版   2025-05-06 06:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
苹果的AirPlay协议和AirPlay软件开发工具包（SDK）中的一系列安全漏洞使未打补丁的第三方和苹果设备暴露于各种攻击中，包括远程代码执行。  
  
网络安全公司Oligo Security的安全研究人员发现并报告了这些漏洞，他们可以利用零点击和一键式RCE攻击、中间人（MITM）攻击和拒绝服务（DoS）攻击，以及绕过访问控制列表（ACL）和用户交互，获得敏感信息的访问权限，并读取任意本地文件。  
  
Oligo向苹果披露了23个安全漏洞，苹果于3月31日发布了针对iphone和ipad （iOS 18.4和iPadOS 18.4）、mac （macOS Ventura 13.7.5、macOS Sonoma 14.7.5和macOS Sequoia 15.4）和Apple Vision Pro （visionOS 2.4）设备的安全更新来解决这些漏洞（统称为“AirBorne”）。  
  
该公司还修补了AirPlay音频SDK、AirPlay视频SDK和CarPlay通信插件。  
  
虽然  
“AirBorne”  
漏洞只能被攻击者通过无线网络或点对点连接在同一网络上利用，但它们允许接管易受攻击的设备，并使用访问作为启动台来破坏同一网络上其他启用airplay的设备。  
  
Oligo的安全研究人员表示，他们能够证明攻击者可以使用两个安全漏洞（CVE-2025-24252和CVE-2025-24132）来创建可蠕虫的零点击RCE漏洞。  
  
此外，CVE-2025-24206用户交互绕过漏洞允许威胁者绕过AirPlay请求的“接受”点击要求，并可以与其他漏洞链接以发起零点击攻击。  
  
这意味着攻击者能够控制某些支持 AirPlay 的设备，并实施诸如部署恶意软件之类的操作，这种恶意软件会传播到受感染设备所连接的任何本地网络中的设备。这可能会导致与间谍活动、勒索软件、供应链攻击等相关的其他复杂攻击的发生。  
  
由于 AirPlay 是苹果设备（Mac、iPhone、iPad、Apple TV 等）以及利用 AirPlay 软件开发工具包的第三方设备的一项基础软件，这类漏洞可能会产生深远的影响。  
  
网络安全公司建议用户应立即把所有企业苹果设备和启用 AirPlay 的设备更新到最新软件版本，并要求员工也更新他们所有的个人 AirPlay 设备。  
  
用户还可以采取以下措施来缩小攻击面：将所有苹果设备更新至最新版本；若不使用，禁用 AirPlay 接收器；通过防火墙规则限制仅允许受信任设备访问 AirPlay；仅允许当前用户使用 AirPlay 以缩小攻击面。  
  
苹果公司称，全球活跃的苹果设备（包括 iPhone、iPad、Mac 以及其他设备）超过 23.5 亿台，而 Oligo 估计，还有数千万台支持 AirPlay 的第三方音频设备，如扬声器和电视，这还不包括支持 CarPlay 的汽车信息娱乐系统。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/apple-airborne-flaws-can-lead-to-zero-click-airplay-rce-attacks/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibaTFU29SJNJBHkSkiaOibpzsCl5icnPrcXIsxmX5WS06UNc46jc5XSicpJCjK5DeqozJbtg7ft5SlAZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibaTFU29SJNJBHkSkiaOibpzsbx1Pzfgzgetb7BSCmFad21iamrHG5E7Zib7Sbyh5QhmAiaZV6jc4eWBiaw/640?wx_fmt=png&from=appmsg "")  
  
  
