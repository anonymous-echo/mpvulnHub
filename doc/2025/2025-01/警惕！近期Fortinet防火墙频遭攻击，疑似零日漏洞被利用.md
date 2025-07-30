#  警惕！近期Fortinet防火墙频遭攻击，疑似零日漏洞被利用   
 网络安全与人工智能研究中心   2025-01-17 04:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibydaJdq7j5pbliczZFces7KACvQeb5oDaAp0ibibVtOtU0PuxEyVrBKHr8S07Ar2XCSodMObuE1QAweA/640?wx_fmt=gif&from=appmsg "")  
  
**针对公网暴露的FortiGate设备管理接口的一系列持续攻击，导致未经授权的管理员登录、配置更改、新账号创建以及SSL VPN认证执行。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ezpQRXtYHibydaJdq7j5pbliczZFces7KAfSGibukoms9vz7Wb1fZs9uYHtnAzu5BqOv9yaZSzxXjhkibu9G5CUIUw/640?wx_fmt=jpeg&from=appmsg "")  
  
安全内参1月15日消息，近期一系列针对Fortinet FortiGate防火墙设备的攻击可能源于一个零日漏洞。这些设备的管理接口暴露在互联网上。研究人员发现，攻击者利用这些接口实施了未经授权的管理员登录、修改配置、创建新账号，并执行了SSL VPN认证操作。安全厂商Arctic Wolf的研究人员在最新的博客文章中透露，自2024年12月初首次发现FortiGate设备上的可疑活动以来，他们一直在追踪这一攻击活动。他们观察到，威胁行为者通过访问受影响防火墙的管理接口（固件版本为7.0.14至7.0.16）更改了设备配置。此外，在受侵入的环境中，攻击者还利用DCSync工具提取了凭证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibydaJdq7j5pbliczZFces7KAEzSicEzzGqLUzBgMmTV1mlWM5A2X2S6EqvQX5iaHalYpIKPGYrKUwtAA/640?wx_fmt=png&from=appmsg "")  
  
  
2024年12月，Arctic Wolf发布了一份安全公告，披露了这起攻击事件。最新的博客文章提供了更深入的细节，指出攻击者可能利用了一个零日漏洞。然而，研究人员尚未“明确确认”初始攻击的具体方法。但结合受影响组织的时间线紧凑性及固件版本范围，他们推测，攻击者正在利用一个尚未公开披露的漏洞。  
研究人员补充道，此次攻击活动的受害者分布广泛，没有集中于特定行业或组织规模，这表明攻击是“机会主义性质的，而非刻意的系统性目标攻击”。  
研究人员尚未提供关于此次攻击活动范围或规模的详细信息。  
  
  
**Fortinet管理员控制台遭到攻击滥用**  
  
  
  
根据博客文章，与合法的防火墙活动相比，研究人员发现攻击者“频繁使用来自少量异常IP地址的jsconsole界面”进行恶意活动。研究人员解释道，FortiGate下一代防火墙产品提供了一项标准且“便捷”的功能，允许管理员通过基于Web的管理界面访问命令行界面（CLI）。  
他们写道：“根据FortiGate的知识库，当管理员通过基于Web的CLI控制台进行更改时，用户界面会记录为jsconsole，同时记录下进行更改的源IP地址。而通过SSH进行更改时，则会记录为SSH。”  
尽管尚未直接确认这些命令是否被用于此次攻击活动，但研究人员观察到的行为模式与通过jsconsole调用的方式高度相似。  
研究人员补充：“根据入侵过程中观察到的战术和基础设施差异，此次攻击活动可能涉及多个攻击者或团体，但jsconsole的使用贯穿始终，成为攻击活动的共同特征。”  
  
  
**四阶段攻击活动仍在持续**  
  
  
  
研究人员将此次攻击活动划分为四个阶段，自2024年11月中旬开始：  
  
  
第一阶段：漏洞扫描（11月中旬）  
  
  
第二阶段：侦察活动（11月底）  
  
  
第三阶段：SSLVPN配置（12月初）  
  
  
第四阶段：横向移动（12月中旬至下旬）  
  
他们指出，这一攻击活动仍在持续，并可能在未来发现更多相关活动。  
研究人员解释：“这些阶段划分基于观察到的恶意配置更改类型及威胁行为者在获得访问权限后采取的具体行动，这些行动发生在多个受害组织的受攻击防火墙设备上。”  
通常，通过异常IP地址的jsconsole登录尝试次数从数百到数千次不等，贯穿了攻击活动的四个阶段。  
他们写道：“多数会话的持续时间极短，相关登出事件通常在1秒内甚至更短时间内发生。在某些情况下，同一秒内会出现多次登录或登出事件，每秒多达4次。”  
  
  
**不要将管理接口暴露在公网上**  
  
  
  
Fortinet设备长期以来是威胁行为者的热门目标，其产品中的漏洞经常被广泛利用以实施网络入侵。研究人员建议，为了预防攻击，组织应避免将任何Fortinet设备的管理接口暴露在公共互联网上，而应仅限受信任的内部用户访问。  
他们在文章中写道：“将这些接口暴露在公共互联网上，会扩大威胁行为者的攻击面，从而使本应仅供受信任管理员使用的功能面临风险。”  
此外，研究人员建议管理员遵循以下最佳安全实践：定期更新设备固件，修补漏洞和其他安全问题；为所有防火墙设备配置syslog监控，以便尽早捕获恶意活动的迹象。  
  
**参考资料：darkreading.com**  
  
  
来源｜“安全内参”公众号  
  
编辑｜风东曾  
  
审核｜秦川原  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibydaJdq7j5pbliczZFces7KA10w37Kxs1E6icEscDTvc8EiaDZoeQA7JFWzPibzRHXPa4trFiahbju0WcQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
