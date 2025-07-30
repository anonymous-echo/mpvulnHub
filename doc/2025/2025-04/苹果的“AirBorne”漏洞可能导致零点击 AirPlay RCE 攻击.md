#  苹果的“AirBorne”漏洞可能导致零点击 AirPlay RCE 攻击   
 独眼情报   2025-04-30 04:53  
  
![Apple](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnT0oVWcJ27tbSpZcY13ZicDwWRBxXy4KF4XaAB2nNh13Vn5Z7K6mFHoMNV6zkvGcfUADmWstzcGMicg/640?wx_fmt=jpeg&from=appmsg "")  
  
苹果  
  
苹果 AirPlay 协议和 AirPlay 软件开发工具包 (SDK) 中的一组安全漏洞使未修补的第三方和苹果设备容易受到各种攻击，包括远程代码执行。  
  
根据发现并报告这些漏洞的网络安全公司 Oligo Security 的安全研究人员的说法，这些漏洞可被用于零点击和一点击 RCE 攻击、中间人 (MITM) 攻击和拒绝服务 (DoS) 攻击，以及绕过访问控制列表 (ACL) 和用户交互，以获取敏感信息和读取任意本地文件。  
  
总之，Oligo 向苹果披露了 23 个安全漏洞，苹果发布了安全更新来解决这些漏洞（统称为“AirBorne”），这些更新于 3 月 31 日发布，适用于 iPhone 和 iPad (iOS 18.4 和 iPadOS 18.4)、Mac (macOS Ventura 13.7.5, macOS Sonoma 14.7.5, 和 macOS Sequoia 15.4) 以及 Apple Vision Pro (visionOS 2.4) 设备。  
  
该公司还修补了 AirPlay 音频 SDK、AirPlay 视频 SDK 和 CarPlay 通信插件 。  
  
虽然 AirBorne 漏洞只能被攻击者通过无线网络或点对点连接在同一网络上利用，但它们允许接管易受攻击的设备，并利用访问权限作为启动平台来攻击同一网络上的其他支持 AirPlay 的设备。  
  
Oligo 的安全研究人员表示，他们能够证明攻击者可以使用两个安全漏洞（CVE-2025-24252 和 CVE-2025-24132）来创建可蠕虫传播的零点击 RCE 漏洞。  
  
此外，CVE-2025-24206 用户交互绕过漏洞使威胁行为者能够绕过 AirPlay 请求上的“接受”点击要求，并可以与其他漏洞链式利用以发起零点击攻击。  
  
"这意味着攻击者可以控制某些支持 AirPlay 的设备，并执行诸如部署恶意软件等操作，该恶意软件会传播到受感染设备连接的任何本地网络上的设备。这可能导致与间谍活动、勒索软件、供应链攻击等相关的其他复杂攻击的发生，Oligo 警告说 。"  
  
"由于 AirPlay 是 Apple 设备（Mac、iPhone、iPad、AppleTV 等）以及利用 AirPlay SDK 的第三方设备的基本软件，这类漏洞可能会产生深远的影响。"  
  
这家网络安全公司建议各组织立即将其企业 Apple 设备和支持 AirPlay 的设备更新到最新的软件版本，并要求员工也更新其所有个人 AirPlay 设备。  
  
用户可以采取的其他措施来减少攻击面，包括将所有 Apple 设备更新到最新版本，如果未使用则禁用 AirPlay 接收器，使用防火墙规则将 AirPlay 访问限制为受信任的设备，并通过仅允许当前用户使用 AirPlay 来减少攻击面。  
  
苹果表示，全球有超过 23.5 亿台活跃的苹果设备 （包括 iPhone、iPad、Mac 等），Oligo 估计还有数千万台第三方音频设备，如扬声器和电视，支持 AirPlay，这还不包括支持 CarPlay 的汽车信息娱乐系统。  
>   
> 还是那句老话：有更新及时更新  
  
  
  
