#  超过 2,000 个 Palo Alto 防火墙遭到最近修补的零日漏洞攻击   
Rhinoer  犀牛安全   2024-11-27 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHrzGGf2sIrKohdM7JlPpgpGoV3tGnG1ALpqbwryc5XSianBeaHyIJHXzQ/640?wx_fmt=png&from=appmsg "")  
  
黑客利用两个最近修补的零日漏洞发起攻击，已经攻破了 Palo Alto Networks 的数千个防火墙。  
  
这两个安全漏洞分别是PAN-OS 管理 Web 界面中的身份验证绕过 ( CVE-2024-0012 )，远程攻击者可利用该漏洞获取管理员权限；以及 PAN-OS 权限提升 ( CVE-2024-9474 )，可帮助他们以 root 权限在防火墙上运行命令。  
  
虽然 CVE-2024-9474 于本周一披露，但该公司在 11 月 8 日首次警告客户限制对其下一代防火墙的访问，因为存在潜在的 RCE 漏洞（上周五被标记为 CVE-2024-0012）。  
  
Palo Alto Networks 仍在调查利用这两个漏洞针对“有限数量的设备管理 Web 界面”进行的持续攻击，并且已经观察到攻击者投放恶意软件并在受感染的防火墙上执行命令，并警告称连锁攻击可能已经存在。  
  
该公司周三表示：“2024 年 11 月 18 日报告的这一原始活动主要源自已知的匿名 VPN 服务代理/隧道流量的 IP 地址。”  
  
“目前，据 Unit 42 评估，链接 CVE-2024-0012 和 CVE-2024-9474 的功能漏洞已公开，这将引发更广泛的威胁活动。”  
  
尽管该公司表示，此次攻击仅影响“极少数 PAN-OS”防火墙，但威胁监控平台 Shadowserver 周三报告称，其正在追踪超过 2,700 台存在漏洞的 PAN-OS 设备。  
  
Shadowserver 还在追踪被入侵的 Palo Alto Networks 防火墙的数量，并表示自此次攻击活动开始以来，已有大约 2,000 个防火墙遭到黑客攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBndyYW7UXUuic1oZOU3DLXHr9RApickr2brQWrljxv59yHb7lY5LY6jso7FRfpkO1Pmt8ZicL9YdGIHQ/640?wx_fmt=png&from=appmsg "")  
  
CISA 已将这两个漏洞添加到其已知被利用漏洞目录中，并要求联邦机构在 12 月 9 日之前的三周内修补其防火墙。  
  
11 月初，它还警告攻击者利用Palo Alto Networks Expedition 防火墙配置迁移工具中的另一个关键的缺失身份验证漏洞 ( CVE-2024-5910 )，该漏洞已于 7 月修补，可用于重置暴露在互联网上的 Expedition 服务器上的应用程序管理员凭据。  
  
今年早些时候，该公司的客户还必须修补另一个最高严重程度且被积极利用的 PAN-OS 防火墙漏洞 ( CVE-2024-3400 )，该漏洞影响了超过 82,000 台设备。CISA 还将CVE-2024-3400 添加到其 KEV 目录中，要求联邦机构在七天内保护其设备。  
  
帕洛阿尔托网络公司周三“强烈”建议其客户通过限制对内部网络的访问来保护防火墙的管理接口。  
  
该公司表示：“如果您按照我们推荐的最佳实践部署指南，将访问限制为仅受信任的内部 IP 地址，从而确保对管理 Web 界面的访问安全，则这些问题的风险将大大降低。”  
  
  
信息来源：  
BleepingComputer  
  
