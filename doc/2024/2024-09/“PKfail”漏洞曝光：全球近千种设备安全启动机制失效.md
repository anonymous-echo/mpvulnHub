#  “PKfail”漏洞曝光：全球近千种设备安全启动机制失效   
 商密君   2024-09-22 18:49  
  
**近日安全研究人员发现从游戏机到总统大选投标机的海量设备仍然使用不安全的测试密钥，容易受到UEFI bootkit恶意软件的攻击。**  
  
  
**安全启动不安全**  
  
  
  
在近期的安全研究中，一项涉及设备制造行业安全启动（Secure Boot）保护机制的供应链失败问题引发了广泛关注。此次事件波及的设备型号范围远比之前已知的要广泛得多，受影响的设备涵盖了ATM机、POS机、甚至投票机等多个领域。  
  
  
这一问题源自于过去十年间，数百种设备型号中使用了非生产环境的测试平台密钥，这些密钥在其根证书中标注了“DO NOT TRUST”（请勿信任）等警示语，此类密钥原本应仅用于测试环境，但设备制造商却将其应用于生产系统。  
  
  
平台密钥作为加密的“信任根”锚定了硬件设备与其运行的固件之间的信任关系，确保安全启动机制正常运行。然而，由于大量用于测试安全启动主密钥的私钥被泄漏，极大地削弱了这一安全机制的有效性。研究发现，2022年甚至有人将一部分私钥在GitHub上公开发布。这些信息为攻击者提供了必要条件，能够通过植入“根工具包”（Rootkits）等恶意软件，破坏设备的UEFI（统一可扩展固件接口）安全启动保护。  
  
  
**500多种设备存在隐患**  
  
  
  
此次供应链安全事件被Binarly命名为“PKfail”（CVE-2024-8105），意指平台密钥（Platform Key）失效。此次失败展示了供应链复杂性已超出用户当前的风险管理能力，特别是在涉及第三方供应商时。不过，研究人员指出，这一风险完全可以通过“安全设计理念”进行规避和缓解。  
  
  
根据Binarly的最新报告，受此问题影响的设备型号远超此前的认知。Binarly的研究工具在过去几个月中收集到了10095个固件样本，其中791个（约占8%）包含了非生产密钥。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvYVVibClDxYGLicw8H002giaWeAfiaia18IORecNSSiajH1iaavV6T8g1O2ic9fiade8GRTH1wIRt8T61dJ7Ew/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
受PKfail影响的固件数量 来源：Binarly  
  
  
最初，Binarly识别出了大约513种设备型号使用了测试密钥，目前一数字已增长至972种。此外，最早报告的215个受影响型号中，有490个型号使用了在GitHub上公开的密钥。研究人员还发现了四个新的测试密钥，使得总数达到了约20个。  
  
  
此前发现的密钥均来自AMI，这是一家为设备制造商提供UEFI固件开发工具包的主要供应商之一。自7月以来，Binarly还发现了AMI的其他两大竞争对手Insyde和Phoenix的密钥同样存在问题。  
  
  
更多的受影响设备还包括：  
  
- Hardkernel的odroid-h2、odroid-h3和odroid-h4  
  
- Beelink Mini 12 Pro  
  
- Minisforum HX99G  
  
Binarly进一步指出，受影响的设备不仅限于桌面电脑和笔记本电脑，还包括大量医疗设备、游戏机、企业级服务器、ATM机、销售终端设备，甚至包括投票机！由于目前尚无修复方案，研究人员基于保密协议未披露具体的设备型号。Binarly发布了“PKfail扫描仪”，供应商可以自行上传固件映像查看是否使用了测试密钥。  
  
  
此次事件表明，安全启动作为一种设备预启动阶段的加密保护机制，尽管被广泛应用于政府承包商和企业环境中，但其安全性依然存在隐患，其供应链管理中存在重大漏洞。  
  
  
参考链接：  
  
http://www.binarly.io/blog/pkfail-two-months-later-reflecting-on-the-impact  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：GoUpSec  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  
