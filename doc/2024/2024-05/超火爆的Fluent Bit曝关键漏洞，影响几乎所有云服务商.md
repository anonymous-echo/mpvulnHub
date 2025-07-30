#  超火爆的Fluent Bit曝关键漏洞，影响几乎所有云服务商   
FreeBuf  商密君   2024-05-24 21:40  
  
Fluent Bit 的一个关键漏洞可被用于拒绝服务和远程代码执行攻击，所有主要云服务商都可能受到影响。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38IsDicWmQm5RfkmSibGJMzJOZL6pyxpEjbw7ciaWvdqn00kXmEhX2AEknqibCHM9AnQXpIkHdEbJzZ1A/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
Fluent Bit是一款非常流行的日志和度量解决方案，适用于Windows、Linux和macOS，主要存在于Kubernetes发行版本中，包括亚马逊AWS、谷歌GCP和微软Azure的发行版。  
  
  
截至 2024 年 3 月，Fluent Bit 的下载和部署次数已超过 130 亿次，比 2022 年 10 月报告的 30 亿次下载量有了大幅增长。  
  
  
Crowdstrike 和 Trend Micro 等网络安全公司以及思科、VMware、英特尔、Adobe 和戴尔等许多科技公司也在使用 Fluent Bit。  
  
  
Tenable 安全研究人员将该漏洞称为 Linguistic Lumberjack，并将其追踪为 CVE-2024-4323。据悉，该漏洞是在 2.0.7 版本中引入的，是由 Fluent Bit 的嵌入式 HTTP 服务器在解析跟踪请求时的堆缓冲区溢出弱点引起的。  
  
  
尽管未经认证的攻击者可以轻松利用该安全漏洞触发拒绝服务或远程捕获敏感信息，但如果有合适的条件和足够的时间创建可靠的漏洞，他们也可以利用该漏洞获得远程代码执行。  
  
  
Tenable 安全研究人员表示：虽然堆缓冲区溢出是可以被利用的，但创建一个可靠的漏洞不仅困难重重，而且需要耗费大量时间。  
  
  
研究人员认为，最直接、最主要的风险是那些与轻易实现 DoS 和信息泄露有关的风险。  
  
  
**随 Fluent Bit 3.0.4 发布的补丁程序**  
  
  
  
4 月 30 日，Tenable 向供应商报告了该安全漏洞，并于 5 月 15 日提交了该漏洞的修补程序，包含该补丁的正式版本预计将随 Fluent Bit 3.0.4 一起发布。  
  
  
Tenable 还通过其漏洞披露平台向微软、亚马逊和谷歌通报了这一重大安全漏洞。  
  
  
Tenable 方面上周三（5 月 15 日）表示：在所有受影响的平台修复之前，那些已经在基础架构上部署了该日志工具的客户，可以通过限制授权用户和服务访问 Fluent Bit 的监控 API 来缓解这一问题。  
  
  
如果用不到这个易受攻击的 API 端点，也可以将其禁用，这样可以最大程度地避免安全风险。  
  
  
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
  
