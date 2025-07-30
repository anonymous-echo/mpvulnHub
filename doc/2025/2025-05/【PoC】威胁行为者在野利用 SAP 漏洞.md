#  【PoC】威胁行为者在野利用 SAP 漏洞   
 独眼情报   2025-05-10 07:07  
  
国内有 1500 左右的受影响设备。之前也发过，没人重视，再发一遍。  
  
[SAP NetWeaver 中的关键漏洞受到主动利用的威胁](https://mp.weixin.qq.com/s?__biz=MzkzNDIzNDUxOQ==&mid=2247498299&idx=4&sn=7fc6a5afafb1dcc87ce8e0bd169e98c9&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTXgqOsyCTOHArnqygkG6nUM6zZPggOTdmITZ37whoEUluo4FGIwfdicDujCryC1Pg6KKYMrfGuCqA/640?wx_fmt=png&from=appmsg "")  
  
CVE-2025-31324 是一个影响 SAP NetWeaver Visual Composer 7.x 的严重反序列化漏洞，该漏洞允许攻击者将恶意二进制文件（例如 Web Shell）上传到易受攻击的服务器，从而完全控制未打补丁的系统。  
  
至少从 4 月 29 日起，CVE 就在野外被积极利用。  
  
在调查此漏洞的主动利用情况的过程中，我们发现了疑似属于威胁行为者的恶意基础设施，我们目前将其标记为 Chaya_004（根据我们对未具名威胁行为者的惯例）。该基础设施包括一个托管 Supershell 后门的服务器网络，以及各种渗透测试工具。  
## CVE-2025-31324：SAP 漏洞概述  
  
CVE-2025-31324 允许攻击者通过 SAP NetWeaver Visual Composer 中存在漏洞的端点上传恶意 Web Shell，从而实现远程代码执行 (RCE)。攻击者已展示出以下一致的利用模式：  
- 针对 /developmentserver/metadatauploader  
 端点的 POST 请求。  
  
- 部署 Web shell，包括名为 helper.jsp、cache.jsp 的文件，以及其他具有随机 8 个字母名称的文件，例如“ssonkfrd.jsp”。  
  
- 使用 curl 从外部基础设施下载更多恶意负载。  
  
Visual Composer 是 SAP 基于 Web 的工具，用于以可视化方式创建业务应用程序。它运行在 NetWeaver 服务器上，这些服务器通常服务于 SAP 业务套件中的其他应用程序，例如客户关系管理 (CRM)、供应链管理 (SCM) 和供应商关系管理 (SRM)。  
  
如果不进行修补，利用 CVE-2025-31324 可能会导致：  
- **服务中断**  
 ——Web shell 访问可能允许攻击者破坏或删除通用描述发现和集成 (UDDI) 条目，从而破坏 CRM、SCM 或 SRM 等 SAP 模块之间的通信。  
  
- **信息泄露**  
 ——服务元数据可以暴露内部 API、身份验证方法和系统配置。  
  
- **凭证拦截**  
 ——操纵的服务端点可能被用来获取用户凭证或注入恶意内容。  
  
- **横向移动**  
 ——从 Visual Composer，攻击者可以转向更关键的 SAP 组件，例如网关、消息服务器或 HANA 数据库。  
  
## 漏洞利用迹象  
  
为了识别当前的攻击活动和参与者，我们使用了三个数据源：  
- **针对应用执行环境的扫描。**  
 自 4 月 25 日（CVE 发布后的第二天）以来，已有多种扫描工具和概念验证 (PoC) 漏洞被公开。如下图所示，我们从 4 月 29 日开始注意到针对 AEE 的扫描。针对“/developmentserver/metadatauploader  
”的扫描（用于查找易受攻击的服务器）自 4 月 29 日起持续增长，而针对“/irj/*.jsp”  
的扫描（用于查找受感染的服务器）仅在 4 月 29 日至 4 月 30 日期间进行。我们注意到有 37 个唯一 IP 地址正在扫描“/developmentserver/metadatauploader  
”，有 14 个唯一 IP 地址正在扫描“/irj/*.jsp  
”。与前一次扫描相关的所有 IP 均位于 Microsoft ASN 上，与后一次扫描相关的所有 IP 均位于 Amazon ASN 上。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnTXgqOsyCTOHArnqygkG6nU8BlyMfxxahknpokTHfp3VherfaBPSXibWlJzewuvn79iab2OZmGXpdCQ/640?wx_fmt=png&from=appmsg "")  
- **针对客户的漏洞利用尝试。**  
 漏洞利用尝试主要出现在制造环境中，在这些环境中，SAP 系统被入侵可能会对运营和安全造成广泛的影响。同样值得注意的是，在这些环境中，我们观察到防御扫描期间系统崩溃的报告，这表明系统存在漏洞或暴露。我们观察到 13 个不同的 IP 地址在客户网络上试图利用此漏洞。这些地址属于以下自治系统 (AS)：  
  
- AS12876（Scaleway SAS）——法国托管服务提供商，有多个 IP 被记录为暴力攻击目标。  
  
- AS51167（Contabo GmbH）——德国托管服务提供商，以提供低成本 VPS 服务而闻名，但有时会被威胁行为者滥用。  
  
- AS40021（Nubes, LLC）——一家在美国注册的提供商，提供 VPN 服务器和 Tor 服务。  
  
- AS41314 (ECO TRADE Sp. z oo) – 一家波兰小型 ASN，似乎属于一家合法食品制造企业。漏洞利用尝试中使用的 IP 可能已被泄露。  
  
- **追踪对手基础设施。**  
 在其中一次攻击中，我们恢复了一个名为“config”的 ELF 二进制文件 ( 888e953538ff668104f838120bc4d801c41adb07027db16281402a62f6ec29ef) ，并从中提取了 IP 地址 47.97.42[.]177。该 IP 地址托管了一个 SuperShell 登录界面，网址为 http://47.97.42[.]177:8888/supershell/login。SuperShell 是一个基于 Web 的反向 Shell，由一位名为“tdragon6”的中文开发者使用 Go 语言开发。这一发现促使我们绘制并追踪这些漏洞背后的威胁行为者基础设施。  
  
## 绘制活动地图：揭露 Chaya_004 基础设施  
  
在托管 Supershell 的同一 IP 地址（47.97.42[.]177）上，我们还发现了其他几个开放端口，包括 3232/HTTP，它使用一个异常的自签名证书冒充 Cloudflare，具有以下属性： Subject DN: C=US  
 、 O=Cloudflare, Inc  
 、 CN=:3232  
 。  
  
使用 Censys，我们识别出 20 个 ASN 和 8 个国家/地区的 114 个 IP 地址，这些 IP 地址的证书上共享相同的不常见 CN。使用 FOFA，我们又发现 17 个 ASN 和 19 个国家/地区的 464 个 IP 地址具有相同的属性。（此处省略一些内容，🐶保命）  
  
。。。。。。。。。  
  
其他 ASN 主要位于美国、新加坡和日本，在其他几个国家也有有限的存在。  
  
其中 787 个 IP 地址开放了 3232 端口，这与证书中异常的 CN 值相符，有力地证明了该攻击活动的一致性。其他常开放的端口包括 443（51 个）、2096（12 个）、22（9 个）、3333（6 个）和 2222（6 个）。  
  
在绘制基础设施图之后，我们探索了可访问的 Web 界面以识别已部署的工具，并发现以下内容：  
- NPS ：“轻量级、高性能、强大的内网穿透代理服务器”的中文 GitHub 仓库  
  
- SuperShell ：主要后门/管理界面  
  
- SoftEther VPN ：用于与 45.94.43[.]41 上受感染基础设施进行安全通信的 VPN 客户端  
  
- NHAS：渗透测试工具包（这个是啥工具啊？不是很懂，有没懂哥？）  
  
- Cobalt Strike：商业红队工具  
  
- 资产侦察灯塔 (ARL)：资产发现框架的中文 GitHub 存储库  
  
- Pocassit ：漏洞扫描实用程序的中文 GitHub 存储库  
  
- Gosint ：情报收集框架  
  
- GO Simple Tunnel ：一个“用 Go 编写的简单隧道”的中文 GitHub 存储库  
  
攻击者使用东大云服务提供商和多款中文工具，这表明该组织可能位于东大，我们将其命名为 Chaya_004。围绕已识别的基础设施进行分析，我们发现了与 Chaya_004 相关的更多发现：  
- IP 地址 49.232.93[.]226，曾用于传播恶意软件样本，包括 svchosts.exe  
 ( f1e505fe96b8f83c84a20995e992b3794b1882df4954406e227bd7b75f13c779  
 )。该样本带有 Triage 水印。 在 28 个主要位于东大的 IP 地址中也发现了相同的水印，可能与之前观察到的活动有关。该样本使用域名 http://search-email[.]com:443/ServiceLogin/_/kids/signup/eligible  
 进行 C2 通信。  
  
- 托管在 http://8.210.65[.]56:5000/的自动渗透测试工具，具有以下平台功能：  
  
- 资产侦察模块（Hunter、Fofa、Quake、SecurityTrails、Subfinder）  
  
- 漏洞扫描模块（Lighthouse、Xray proxy、AWVS）  
  
- 任务编排和报告功能  
  
## 缓解建议  
  
防御 CVE-2025-31324：  
1. **立即应用 SAP 补丁**  
 – SAP 已于 2025 年 4 月补丁日发布了修复程序。请确保应用适用于 NetWeaver AS Java 7.50–7.52 版本的相应安全说明。  
  
1. **限制对元数据上传器服务的访问**  
 ——使用防火墙策略或 SAP Web Dispatcher 限制 /developmentserver/metadatauploader 端点的暴露。内部访问应仅限于授权管理员。  
  
1. **禁用未使用的 Web 服务**  
 – 如果 Visual Composer 服务不是必需的，请考虑将其完全禁用。  
  
1. **监控异常**  
 ——部署实时监控，以发现服务条目的异常访问或变化，尤其是在维护时段之外。  
  
1. **进行定期安全评估**  
 ——确保 SAP NetWeaver 端点包含在常规渗透测试和漏洞扫描中。  
  
## IoC 和其他威胁情报来源  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;text-align: left;"><section><span leaf="">IoC</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;text-align: left;"><section><span leaf="">描述</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">130.131.160[.]24</span><span leaf=""><br/></span><span leaf="">135.119.17[.]221</span><span leaf=""><br/></span><span leaf="">135.233.112[.]100</span><span leaf=""><br/></span><span leaf="">172.212.216[.]128</span><span leaf=""><br/></span><span leaf="">172.212.219[.]49</span><span leaf=""><br/></span><span leaf="">20.118.200[.]88</span><span leaf=""><br/></span><span leaf="">20.118.33[.]20</span><span leaf=""><br/></span><span leaf="">20.15.201[.]23</span><span leaf=""><br/></span><span leaf="">20.150.192[.]195</span><span leaf=""><br/></span><span leaf="">20.150.192[.]39</span><span leaf=""><br/></span><span leaf="">20.150.202[.]153</span><span leaf=""><br/></span><span leaf="">20.150.202[.]55</span><span leaf=""><br/></span><span leaf="">20.150.205[.]154</span><span leaf=""><br/></span><span leaf="">20.163.15[.]93</span><span leaf=""><br/></span><span leaf="">20.163.2[.]229</span><span leaf=""><br/></span><span leaf="">20.163.57[.]193</span><span leaf=""><br/></span><span leaf="">20.163.60[.]206</span><span leaf=""><br/></span><span leaf="">20.163.74[.]20</span><span leaf=""><br/></span><span leaf="">20.168.121[.]119</span><span leaf=""><br/></span><span leaf="">20.169.105[.]57</span><span leaf=""><br/></span><span leaf="">20.169.48[.]134</span><span leaf=""><br/></span><span leaf="">20.169.48[.]59</span><span leaf=""><br/></span><span leaf="">20.171.29[.]48</span><span leaf=""><br/></span><span leaf="">20.171.30[.]196</span><span leaf=""><br/></span><span leaf="">20.171.30[.]224</span><span leaf=""><br/></span><span leaf="">20.171.9[.]108</span><span leaf=""><br/></span><span leaf="">20.29.24[.]163</span><span leaf=""><br/></span><span leaf="">20.29.42[.]207</span><span leaf=""><br/></span><span leaf="">20.46.234[.]65</span><span leaf=""><br/></span><span leaf="">20.65.193[.]234</span><span leaf=""><br/></span><span leaf="">20.65.194[.]105</span><span leaf=""><br/></span><span leaf="">20.65.194[.]9</span><span leaf=""><br/></span><span leaf="">20.65.195[.]124</span><span leaf=""><br/></span><span leaf="">20.65.195[.]20</span><span leaf=""><br/></span><span leaf="">20.98.152[.]33</span><span leaf=""><br/></span><span leaf="">40.67.161[.]44</span><span leaf=""><br/></span><span leaf="">52.248.40[.]89</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">观察到 AEE 上 /developmentserver/metadatauploader/ 的扫描</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">13.228.100[.]218</span><span leaf=""><br/></span><span leaf="">13.58.39[.]15</span><span leaf=""><br/></span><span leaf="">18.142.70[.]42</span><span leaf=""><br/></span><span leaf="">18.159.188[.]112</span><span leaf=""><br/></span><span leaf="">18.204.33[.]8</span><span leaf=""><br/></span><span leaf="">3.12.99[.]176</span><span leaf=""><br/></span><span leaf="">3.19.125[.]50</span><span leaf=""><br/></span><span leaf="">3.229.147[.]107</span><span leaf=""><br/></span><span leaf="">3.65.236[.]123</span><span leaf=""><br/></span><span leaf="">3.65.237[.]228</span><span leaf=""><br/></span><span leaf="">3.77.117[.]203</span><span leaf=""><br/></span><span leaf="">34.193.126[.]209</span><span leaf=""><br/></span><span leaf="">35.157.196[.]116</span><span leaf=""><br/></span><span leaf="">52.74.236[.]95</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">观察到 AEE 上 /irj/*.jsp 的扫描</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">163.172.146[.]243</span><span leaf=""><br/></span><span leaf="">212.28.183[.]85</span><span leaf=""><br/></span><span leaf="">212.47.227[.]221</span><span leaf=""><br/></span><span leaf="">212.56.34[.]86</span><span leaf=""><br/></span><span leaf="">31.220.89[.]227</span><span leaf=""><br/></span><span leaf="">51.15.223[.]138</span><span leaf=""><br/></span><span leaf="">51.158.64[.]240</span><span leaf=""><br/></span><span leaf="">51.158.97[.]138</span><span leaf=""><br/></span><span leaf="">89.117.18[.]228</span><span leaf=""><br/></span><span leaf="">89.117.18[.]230</span><span leaf=""><br/></span><span leaf="">94.72.102[.]203</span><span leaf=""><br/></span><span leaf="">94.72.102[.]225</span><span leaf=""><br/></span><span leaf="">94.72.102[.]253</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">观察到有人试图利用客户网络上的漏洞</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">47.97.42[.]177 (Initial SuperShell host)</span><span leaf=""><br/></span><span leaf="">49.232.93[.]226 (malware distribution node)</span><span leaf=""><br/></span><span leaf="">8.210.65[.]56 (automated pentest platform)</span><span leaf=""><br/></span><span leaf="">search-email[.]com (C2 domain)</span><span leaf=""><br/></span><span leaf="">888e953538ff668104f838120bc4d801c41adb07027db16281402a62f6ec29ef (config ELF binary)</span><span leaf=""><br/></span><span leaf="">f1e505fe96b8f83c84a20995e992b3794b1882df4954406e227bd7b75f13c779 (svchosts.exe)</span><span leaf=""><br/></span><span leaf="">Subject DN: C=US, O=Cloudflare, Inc, CN=:3232</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: left;"><section><span leaf="">Chaya_004 基础设施</span></section></td></tr></tbody></table>  
  
CVE-2025-31324 的其他威胁情报来源包括：  
- **PoC 漏洞**  
公开发布： https://github.com/ODST-Forge/CVE-2025-31324_PoC  
  
- **利用分析：**  
Rapid7 博客关于 CVE-2025-31324  
  
- **检测规则（YARA）：**  
Onapsis YARA 规则  
  
  
  
  
