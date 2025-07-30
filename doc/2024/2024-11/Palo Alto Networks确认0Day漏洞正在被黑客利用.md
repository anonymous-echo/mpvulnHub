#  Palo Alto Networks确认0Day漏洞正在被黑客利用   
FreeBuf  商密君   2024-11-18 13:40  
  
近日，全球网络巨头Palo Alto Networks确认旗下0Day漏洞正在被黑客利用。11月8日，Palo Alto Networks发布了一份安全通告，警告客户PAN-OS管理界面中存在一个远程代码执行漏洞，并建议客户确保PAN-OS管理界面访问的安全性。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39tmyyDlVsmZoccz4K8eSN6cHfohWMRZSkY8icEo6XAJ7QsGaGC2Dnia3076fNUJm4F5h7ibvq0ls6lw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
但随着该漏洞的曝光，Palo Alto Networks在11月15日发现已经有黑客/威胁组织正在利用该漏洞，对用户发起网络攻击，主要目标用户是那些暴露在互联网上防火墙管理界面。  
  
  
目前还不清楚该漏洞如何暴露，以及受影响的企业范围。该漏洞也还没有分配CVE标识符，CVSS评分9.3分。Palo Alto Networks表示，他们认为Prisma Access和Cloud NGFW产品不受此漏洞影响。  
  
  
**安全措施和建议**  
  
  
  
目前，Palo Alto Networks正在开发补丁和威胁预防签名，建议客户确保只有来自可信IP地址的访问才能访问防火墙管理界面，而不是从互联网访问。公司指出，大多数防火墙已经遵循了这一Palo Alto Networks和行业的安全最佳实践。  
  
  
其他受影响的产品：除了上述漏洞，美国网络安全机构CISA还表示，他们知道有三个影响Palo Alto Networks Expedition的漏洞在野外被利用。CISA警告，至少有两个影响Palo Alto Networks Expedition软件的漏洞正在被积极利用，并已将这些漏洞添加到其已知被利用漏洞(KEV)目录中，要求联邦文职行政部门机构在2024年12月5日之前应用必要的更新。  
  
  
**屡屡出现0Day漏洞**  
  
  
  
值得一提的是，在2024年3月，Palo Alto Networks防火墙产品也曾被曝存在严重安全漏洞，编号 CVE-2024-3400 ，CVSS 评分达10分，具体涉及PAN-OS 10.2、PAN-OS 11.0 和 PAN-OS 11.1 防火墙版本软件中的两个缺陷。  
  
  
在第一个缺陷中，GlobalProtect 服务在存储会话 ID 格式之前没有对其进行充分验证。Palo Alto Networks 产品安全高级总监 Chandan B. N. 表示，这使得攻击者能够用选择的文件名存储一个空文件。第二个缺陷被认为是系统生成的文件将文件名作为了命令的一部分。  
  
  
值得注意的是，虽然这两个缺陷本身都不够严重，但当它们组合在一起时，就可能导致未经验证的远程 shell 命令执行。  
  
  
Palo Alto Network表示，利用该漏洞实施零日攻击的攻击者实施了两阶段攻击，以便在易受影响的设备上执行命令。该活动被命名为Operation MidnightEclipse，涉及发送包含要执行命令的特制请求，然后通过名为 UPSTYLE 的后门运行。  
  
  
在攻击的第一阶段，攻击者向 GlobalProtect 发送精心制作的 shell 命令而非有效的会话 ID，导致在系统上创建一个空文件，文件名由攻击者命名为嵌入式命令；在第二阶段，定时运行系统作业会在命令中使用攻击者提供的文件名，进而让攻击者提供的命令能以更高的权限执行。利用这种方式，攻击者就能将该漏洞武器化，且不需要在设备上启用遥测功能就能对其进行渗透。  
  
  
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
  
