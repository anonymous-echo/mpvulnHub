#  神漏洞！GE医疗超声设备感染勒索软件，设备停摆、数据遭篡改   
​安全内参  商密君   2024-05-18 19:51  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7ssPd2ZV1sLdkHCCZdua4ncNRuoL1tRxtN1UO22uEv5hYhgFaVNIwaAFbAwBoIcV7JG7ap3ZllnAg/640?wx_fmt=jpeg&from=appmsg&wxfrom=13 "")  
  
  
**GE医疗超声设备存在高危漏洞，在部分限制场景下可被植入勒索软件，篡改患者检查数据，甚至让设备无法使用。**  
  
  
5月17日消息，安全研究人员披露了十多个影响通用电气（GE）医疗旗下Vivid系列超声产品的安全漏洞。恶意攻击者可以利用这些漏洞篡改患者数据，甚至在某些情况下安装勒索软件。  
  
OT安全厂商Nozomi Networks发布技术报告称：“这些漏洞可以造成多方面影响，包括在超声设备上植入勒索软件、访问和篡改存储在易受攻击设备上的患者数据等。”  
  
这些安全问题影响Vivid T9超声系统及其预装的Common Service Desktop网页应用程序。该应用程序暴露在设备的本地主机接口上，允许用户执行管理操作。  
  
另一个受影响的软件程序叫做EchoPAC，安装在医生的Windows工作站上，帮助他们访问多维度的超声、血管和腹部影像。  
  
  
**物理接触后可造成高危害**  
  
  
要成功利用这些漏洞，攻击者首先需要进入医院环境并与设备进行物理交互，之后他们才能利用这些漏洞获得管理员权限，执行任意代码。  
  
在假设的攻击场景中，恶意攻击者可以通过植入勒索软件锁定Vivid T9系统，甚至窃取或篡改患者数据。  
  
最严重的漏洞是CVE-2024-27107（CVSS评分：9.6），涉及使用硬编码凭证。研究人员发现的其他缺陷包括命令注入（CVE-2024-1628）、以不必要的权限执行（CVE-2024-27110、CVE-2020-6977）、路径遍历（CVE-2024-1630、CVE-2024-1629）以及保护机制失效（CVE-2020-6977）。  
  
Nozomi Networks设计的漏洞利用链，通过CVE-2020-6977获取设备的本地访问权限，然后利用CVE-2024-1628实现代码执行。  
  
Nozomi Networks表示：“为了加快攻击速度，攻击者还可以利用暴露的USB端口，插入一只恶意U盘，通过模拟键盘和鼠标，以比人类更快的速度自动执行所有必要步骤。”  
  
或者，攻击者可以使用通过其他手段（如网络钓鱼或数据泄漏）获取的被盗VPN凭证，访问医院的内部网络，扫描易受攻击的EchoPAC设备，然后利用CVE-2024-27107获取对患者数据库的不受限制的访问，彻底破坏其机密性、完整性和可用性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/FzZb53e8g7ssPd2ZV1sLdkHCCZdua4ncQ2udJcKLg6ZsD4emlYRBcUG5QibcBYvGJZeDzRVh2BSdvick2xrxlsTw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
GE医疗发布了一系列公告，表示“现有的缓解措施和控制措施”将这些漏洞带来的风险降到了可接受的水平。  
  
公告指出：“具有物理访问权限的恶意攻击者可能会使设备无法使用，但是这种情况不太可能发生。而且设备的预期用户会看到明确的被攻击迹象。该漏洞只能被具有直接物理访问权限的人利用。”  
  
  
**物联网漏洞频发**  
  
  
这次漏洞披露几周前，研究人员在医学成像软件Merge DICOM Toolkit Windows版中发现了数个安全漏洞（CVE-2024-23912、CVE-2024-23913和CVE-2024-23914）。这些漏洞可用于触发DICOM服务进入拒绝服务状态。这些问题已在这一工具库的v5.18版本中得到解决。  
  
此外，研究人员还在西门子SIMATIC Energy Manager（EnMPro）产品中发现了最高严重性安全漏洞（CVE-2022-23450，CVSS评分：10.0）。远程攻击者可以通过发送恶意制作的对象利用该漏洞以SYSTEM权限执行任意代码。  
  
Claroty安全研究员Noam Moshe表示：“成功利用该漏洞的攻击者可以远程执行代码，并完全控制EnMPro服务器。”  
  
强烈建议用户更新到V7.3 Update 1或更高版本，因为之前的所有版本都包含不安全的反序列化漏洞。  
  
集成于物联网设备中的ThroughTek Kalay平台中也曝出了安全漏洞（CVE-2023-6321到CVE-2023-6324）。攻击者可以利用这些漏洞提升权限、以root身份执行命令，并与受害设备建立连接。  
  
罗马尼亚安全厂商Bitdefender表示：“将这些漏洞结合在一起，可以在本地网络内进行未经授权的root访问和远程代码执行，从而彻底破坏受害设备。只有在设备被本地网络探测到后才有可能实施远程代码执行。”  
  
这些漏洞在2023年10月被披露后，于2024年4月得到了修补。这些漏洞影响了Owlet、Roku和Wyze等供应商生产的婴儿监视器和室内安全摄像头。攻击者可以将这些漏洞链接在一起，在设备上执行任意命令。  
  
Bitdefender 补充道：“这些漏洞的影响远远超出了理论攻击的范围，因为它们直接影响依赖ThroughTek Kalay驱动设备的用户的隐私和安全。”  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：安全内参  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  
