#  英特尔AI模型压缩器现满分漏洞，可导致任意代码执行   
FreeBuf  商密君   2024-05-26 15:30  
  
据Info risk today消息，英特尔公司的人工智能模型压缩软件Neural Compressor 中存在一个最高级别的漏洞，该漏洞在 CVSS 的评分为满分10分，黑客可以在运行受影响版本的系统上执行任意代码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IsDicWmQm5RfkmSibGJMzJOia5VY8hERyicJm6gUrczv1O6E8BiawJH2sIjb7ibq1Otj6mURPSS2gzCBw/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
  
Neural Compressor 软件可帮助公司减少人工智能模型所需的内存量，同时降低缓存丢失率和使用神经网络的计算成本，帮助系统实现更高的推理性能。公司使用开源 Python 库在不同类型的硬件设备上部署人工智能应用，包括那些计算能力有限的设备（如移动设备）。  
  
  
英特尔没有说明有多少公司使用该软件，也没有说明受影响的用户数量，称该漏洞只影响使用 2.5.0 之前版本的用户。  
  
  
在英特尔上周发布的 41 份安全公告中，该漏洞被追踪为 CVE-2024-22476，源于输入验证不当或未对用户输入进行消毒，黑客无需任何特殊权限或用户交互即可远程利用该漏洞，对数据的保密性、完整性和可用性构成很大影响。  
  
  
除此以外，还有另一个漏洞被追踪为 CVE-2024-21792，严重程度为中等，是一个检查时间、使用时间漏洞，可能会让黑客获取未经授权的信息。黑客需要通过本地验证访问存在漏洞的系统才能利用该漏洞。  
  
  
英特尔表示，一个外部安全实体提交了该漏洞报告，但没有说明个人或公司的身份。目前，英特尔已经发布了针对上述两个 Neural Compressor 漏洞的修复程序。  
  
  
去年，研究人员在大型语言模型中发现了几十个漏洞，这些漏洞可能导致操纵实时对话、自我传播零点击漏洞以及利用幻觉传播恶意软件。  
  
  
使用这种软件作为核心组件来构建和支持人工智能产品的公司可能会增加漏洞的影响，英特尔就是一个例子。一个月前，来自 Wiz 的研究人员在流行的人工智能应用开发商 HuggingFace 上发现了现已缓解的漏洞，允许攻击者篡改其注册表上的模型，甚至向其中添加恶意模型。  
  
  
编辑：陈十九  
  
审核：商密君  
  
**征文启事**  
  
大家好，为了更好地促进同业间学术交流，商密君现开启征文活动，只要你对商用密码、网络安全、数据加密等有自己的独到见解和想法，都可以积极向商密君投稿，商密君一定将您的声音传递给更多的人。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXNcXmbiaiaCljdXpwzOEQ9QTBXMibM6rZTOnbTSwTmCXncQLria2vuLGxn8QPtznzBc0as8vBxWIjrWxQ/640?wx_fmt=jpeg "")  
  
来源：FreeBuf  
  
注：内容均来源于互联网，版权归作者所有，如有侵权，请联系告知，我们将尽快处理。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1HyKzSU2XXOdeQx0thlyozF2swQTEN9iaaBNDG0jTKfAgqgdesve8x5IEWNvYxjF6sAWjO1TPCZVsWd0oiaDn3uw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMyyClGk1cttkSBbJicAn5drpXEbFIeChG9IkrslYEylRF4Z6KNaxNafDwr5ibcYaZXdnveQCNIr5kw/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaMcJkA69QYZ9T4jmc3fdN6EA7Qq9A8E3RWcTKhxVEU1QjqOgrJMu2Qg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点分享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaiaRXdw4BFsc7MxzkVZaKGgtjWA5GKtUfm3hlgzsBtjJ0mnh9QibeFOGQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点点赞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1HyKzSU2XXMZPiaDBD8yxbIHiciauWK4tuiaeiaNlRO9954g4VS87icD7KQdxzokTGDIjmCJA563IwfStoFzPUaliauXg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
点在看  
  
