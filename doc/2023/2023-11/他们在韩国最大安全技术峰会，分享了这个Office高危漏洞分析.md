#  他们在韩国最大安全技术峰会，分享了这个Office高危漏洞分析   
 深信服千里目安全技术中心   2023-11-06 19:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EJiaEo3Lq9kovGviamcUSRhAUZNZJBQo5N4XcZkTB8C53iaQkeBia2o6GELGX7IapTC7kApBcEiaONtUeZotlOOefQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**当你**  
  
收到了一个压缩包  
  
或访问了一个远程服务器的文  
件系统  
  
打开了里面的**Word文档**  
  
  
你知道吗，这时你的电脑  
  
可能已经**暴露于黑客前**  
  
**如果不加以修复，可能面临被攻击的风险**  
  
  
日前，**韩国2023 PoC（Power of Community）安全大会**在首尔揭开帷幕，汇聚各国顶级黑客高手，共同探讨安全界的热门议题。深信服首席安全研究员彭峙酿和wh1tc 受邀出席并发表了主题为**《OLE Object are still Dangerous Today :  Exploiting Microsoft Office》**的演讲。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9krtXouC9p31Ap037TQy7whYXfxjt5muCs9udQzGSeNv36NjglaQnfVIe61emL1EhMEsKY4BDRKdfg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**01**  
  
  
  
  
  
**在互联网安全界举办历史最悠久的大会**  
  
**——聊聊那些Office漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EJiaEo3Lq9koBvZOyxXlCgxUkgWQhroq4KoQZJgseC3bEAmOYumIa8C5EJ1ic5icicJn9lLbAlx14xHiakNNy7VoI5A/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
PoC是**韩国最大的安全技术峰会**，2006年一群韩国黑客与安全研究专家决定以“交流技术、分享知识”为目的举办会议，并将其命名为PoC，它是目前**互联网安全界举办历史最悠久的大会之一**，已成为国际知名的安全技术交流峰会。本届大会更是“众星云集”，吸引了全球大量最顶级的软件安全高手和企业代表到场，包括来自Google Project Zero的研究员、著名安全专家James Forshaw和Mark Brand、韩国神童Lokihardt，以及连续多届的Pwn2own Master of Pwn得主——Richardzhu和amat等  
  
  
本次演讲，来自深信服的两位研究员主要分享了**关于W****indows OLE组件的漏洞模式**。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9koBvZOyxXlCgxUkgWQhroq4dwDN1k4gkT4cLglMwa9NYCJjIeo3Yy4CJb4tUGr4ecLLm5HlsMycBw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
彭峙酿指出，Office有着漫长而复杂的漏洞历史。当前在野利用的漏洞量正逐渐减少，攻击者更倾向于使用稳定的**逻辑漏洞**。他以Windows OLE组件漏洞为例，深入阐释这些漏洞的隐藏威胁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9koBvZOyxXlCgxUkgWQhroq4sO7CXHq9P3Marq7sHr2SkibWpib87kbQmJJ0IkX7bv2Ogpn9klIQEd0w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
在Office中，Windows OLE组件组件用于实现上文所述的  
「对象」功能，用户可以在单个文档内编辑其他应用程序的相关内容。Office在加载嵌入了Windows OLE组件的文档时，**会经过三个步骤**：  
  
**1.**从文档中的结构获取CLSID，即对象的全局唯一标识符。  
  
**2.**通过获取的CLSID，调用CoCreateInstance加载对应的对象。这个对应关系可以在注册表中获取。  
  
**3.**  
如果对象是OLE对象，则进一步调用IpersistStorage加载具体的数据。  
  
  
**在以上工作流程中即存在安全隐患**。彭峙酿表示，文档中的CLSID字段攻击者可控的，并非所有CLSID都是OLE对象。因此，在获取CLSID后，Office需要加载对应的对象以确认是否为OLE对象。  
  
  
这种设计缺陷使得**加载CLSID对应对象的过程存在安全问题**，其中一个严重问题是「  
LoadLibrary」函数的错误使用。调用该函数时存在风险，因为可能从当前工作目录加载dll文件，而当前工作目录本身存在风险，可能被攻击者预测。**若用户在未打安全补丁的Windows系统中，打开攻击者制作的恶意Offic文档将导致严重的远程代码执行后果。**  
  
**02**  
  
  
  
  
  
**「aES遏制本次攻击，无需重启业务即可实现防护！」**  
  
**——深信服aES破解隐藏威胁**  
  
作为**全球最流行的办公软件套装之一**，Microsoft Office拥有大量用户数。面对漏洞这一办公文档中的隐藏威胁，**普通用户们该怎么办**？  
  
  
无需过分担心！上文的两位研究员来自于**深信服千里目安全技术中心**  
，该中心构成了深信服系统完整的核心攻防能力体系。这一体系能够将研究成果快速赋能到深信服全线产品和解决方案中，从而强化安全效果。在安全团队发现本次漏洞之后，立即评估了**此Microsoft Office漏洞**  
对用户可能造成的安全隐患，并第一时间将信息同步至深信服统一端点安全管理系统aES产品团队。  
目前，  
针对该漏洞的相关防御措施**已应用于深信服统一端点安全管理系统aES产品轻补丁功能中，****可提前防御此0day漏洞攻击**  
。  
  
  
**轻补丁漏洞免疫**  
，是对此Microsoft Office漏洞的原理性修复。漏洞安全专家根据对相关漏洞信息进行分析与复现，明确定位到漏洞问题的代码（二进制代码）片段位置，通过洞悉漏洞原理，产生漏洞最终的无损防护免疫规则：**在内存中修改系统或应用程序存在漏洞的该代码片段，在无需重启的情况下实现对漏洞利用攻击的防护，真正从源头进行防护**  
。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9koBvZOyxXlCgxUkgWQhroq4ibuL6lKYhafhRWL2tVuZNzl2KuCGaNfImRheSdKQmGWZfj5LHE6Vvtw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
据悉，**深信服aES**围绕终端资产安全生命周期，通过防御、检测、响应赋予终端更为有效的安全能力。在应对**APT高级威胁、变种勒索**的同时，通过多层级检测响应机制、云网端协同联动、威胁情报共享，帮助用户快速发现并精准处置端点安全问题，构建有效的终端安全防护体系。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EJiaEo3Lq9koBvZOyxXlCgxUkgWQhroq4McKPhC2jCrx91Q7epg9J4ZfG6VW1Dmyxgq7IfeEOGa8VTzx8zw3CWw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ZPtdzESiawhdMHyNfDvj0a36SiaN499NjK0BKean9ibV1T8rYe2gLG8OTSjeCB1NesY09JLKujB7DqpO8DGu4HFxw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
作为安全研究的先锋，深信服技术团队具备优异的研究能力，并**连续五年被权威媒体评为“年度杰出安全实验室”。**今年，深信服技术团队——  
  
  
在2023「天府杯」国际网络安全大赛中，来自深信服Deepin Lab（深研究实验室）的k team 仅**用时5秒攻破Windows 11系统，1秒攻破某大用户量办公软件**，最终以总分第三的成绩荣获三等奖。[（点击此处查看详情）](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650581586&idx=2&sn=3ae47c74187354a943ce33687f25c0fd&chksm=beb3aff189c426e7005dc4c779985bf65d55ef73ec65a1ae2e6220576d5ed6f713b4f5135f68&scene=21#wechat_redirect)  
  
  
  
在“MSRC 2023全球Top 100最具价值研究者”榜单中，深信服安全研究员wh1tc & Zhiniang Peng**在“Windows操作系统领域最具价值安全研究员榜单”中登榜第三，在“2023全球Top 100最具价值研究员”登榜第七**。其中，安全研究员Zhiniang Peng**连续四个年度跻身年度总榜前十**。[（点击此处查看详情）](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650578013&idx=1&sn=58bbeb7ad54ba4b6ef0ff45ed39a6370&chksm=beb399fe89c410e8cc7e95b467e5d51ab94cfc3bdeac5c040920d30c82696f6dbbc1ae2eee0b&scene=21#wechat_redirect)  
  
  
  
同时，今年深信服安全研究团队的一篇论文《Detecting Union Type Confusion in Component Object Model.》更是成功**入选了USENIX Security 23——信息安全领域四大顶级学术会议之一**。[（点击此处查看详情）](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650575837&idx=2&sn=5f9820e7e8cdfbb915024d5c1a158ae4&chksm=beb3967e89c41f68afb217e60f3673c03b0e2e7102acae17bca8dcfc9a3975493d4312782167&scene=21#wechat_redirect)  
  
  
  
深信服一直注重网络安全攻防技术研究，利用攻击方视角解决网络安全问题，并将安全研究技术应用到产品实践中。基于千里目安全技术中心多年的技术积累，深信服在国内率先推出了多个前沿安全产品及服务，并在今年  
**首秀自研的安全大模型——安全GPT的技术应用**。截至目前，深信服安全产品及服务已在广大大型企业和机构中应用，覆盖了政府、金融、能源、运营商、医疗、教育、互联网等行业领域，帮助用户构建自身完善的安全体系，致力于让所有用户安全领先一步。  
  
  
未来，深信服将不断提高专业技术造诣，加大对安全研究人才和技术研究层面的投入，深度洞察网络安全威胁，持续为用户网络安全赋能。  
  
  
  
  
**往期推荐******  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EJiaEo3Lq9krtXouC9p31Ap037TQy7whYMJ1VDyrRvbP5E3icAa2sQa1icYdBI4yiafEeIMxwG3mOzUMmjzN7YhVWg/640?wx_fmt=gif "")  
  
  
＋  
  
[Win11首次被攻破，深信服亮剑「天府杯」](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650581586&idx=2&sn=3ae47c74187354a943ce33687f25c0fd&chksm=beb3aff189c426e7005dc4c779985bf65d55ef73ec65a1ae2e6220576d5ed6f713b4f5135f68&scene=21#wechat_redirect)  
  
  
  
  
＋  
  
[首届“天网杯”深信服k team勇夺第二！](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650579125&idx=1&sn=fc6fbfc983b49134aba2f1847eaed6c6&chksm=beb3a51689c42c0060a4ab05caf09b3f7fc61527e75ae80359f65e09f93e4f271081a0af1a56&scene=21#wechat_redirect)  
  
  
  
  
＋  
  
[深信服安全研究员荣登“MSRC 2023全球Top ](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650578013&idx=1&sn=58bbeb7ad54ba4b6ef0ff45ed39a6370&chksm=beb399fe89c410e8cc7e95b467e5d51ab94cfc3bdeac5c040920d30c82696f6dbbc1ae2eee0b&scene=21#wechat_redirect)  
  
  
[100最具价值研究者”榜单！](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650578013&idx=1&sn=58bbeb7ad54ba4b6ef0ff45ed39a6370&chksm=beb399fe89c410e8cc7e95b467e5d51ab94cfc3bdeac5c040920d30c82696f6dbbc1ae2eee0b&scene=21#wechat_redirect)  
  
  
  
  
＋  
  
[连续四年！深信服荣获CNVD年度](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650580233&idx=2&sn=34ff1c49e7e79ab0468312433e7536fb&chksm=beb3a0aa89c429bc8d9b5ccb917f3ceed72e514b2e3046d5be56672ed9e4af523a6f093e17a4&scene=21#wechat_redirect)  
  
  
[「漏洞信息报送突出贡献单位」](http://mp.weixin.qq.com/s?__biz=MjM5MTAzNjYyMA==&mid=2650580233&idx=2&sn=34ff1c49e7e79ab0468312433e7536fb&chksm=beb3a0aa89c429bc8d9b5ccb917f3ceed72e514b2e3046d5be56672ed9e4af523a6f093e17a4&scene=21#wechat_redirect)  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EJiaEo3Lq9ko8vUpIibicDZLLZnDyegoCppibZtU7hnXgt6TjpibO9feZa6Jz1mWCXNIKp54p07wScVvJ3w9JgO69aA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
