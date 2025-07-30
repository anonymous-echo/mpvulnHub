#  Calibre 电子书软件存在严重安全漏洞   
flyme  独眼情报   2024-08-05 11:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnQDNiaWibiagwhWamXlHfWfpGrcgsBPib9TPYTibibutQ3PL21sWMnCkSkEyu445zPQ2Ckhc8uwibTcpehXg/640?wx_fmt=other&from=appmsg "")  
  
Calibre 是一款流行的跨平台电子书管理软件，存在三个重大安全漏洞。STAR Labs SG Pte. Ltd. 的研究人员发现这些漏洞可能会使数百万用户面临各种网络威胁。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnQDNiaWibiagwhWamXlHfWfpGr8IfXId5EtBJUQY6mAbLxsWlVdkqPQPAA1kL3y7dJ6RiceuXbEuj6DTA/640?wx_fmt=other&from=appmsg "")  
  
图片：Starlabs  
  
第一个漏洞被追踪为  
CVE-2024-7008 (CVSS 5.3)  
，它  
使  
  
攻击者能够将恶意 JavaScript 代码注入 Calibre 内容服务器。这可能允许威胁行为者操纵毫无戒心的用户代表他们执行操作，包括对服务器进行未经授权的修改或泄露敏感信息。为了缓解此漏洞，请确保在将用户输入用于生成 HTML 内容之前对其进行适当的验证。具体来说，书籍 ID 应该严格为数字，因此在将输入合并到 HTML 结构之前，验证输入是否仅由数字组成至关重要。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/KgxDGkACWnQDNiaWibiagwhWamXlHfWfpGribNZmEjBOgQEvYImfudCtLdfo2U0GAJBfAupZxaTF5spiajUl8LApCZA/640?wx_fmt=gif&from=appmsg "")  
  
图片：Starlabs  
  
第二个漏洞  
CVE-2024-6781 (CVSS 7.5)  
允许未经身份验证的攻击者或具有某些权限的攻击  
者  
  
读取存储在易受攻击的服务器上的任意文件。这可能导致私人文档、用户数据或其他机密信息的泄露。彻底清理所有用户提供的输入，以防止路径遍历攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/KgxDGkACWnQDNiaWibiagwhWamXlHfWfpGr46DmVO9uJRnLXyiclnz7lNJ89xq9ezat7GDI4opuGBtr05zTP8oU5Sg/640?wx_fmt=gif&from=appmsg "")  
  
图片：Starlabs  
  
  
最严重的漏洞  
CVE-2024-6782 (CVSS 9.8)  
使  
攻击  
  
者能够在受影响的系统上远程执行任意代码。这让他们能够对受感染的设备进行重大控制，从而可能允许他们安装其他恶意软件、窃取数据，甚至对其他连接的系统发起攻击。为了缓解此漏洞，请严格执行可公开访问的端点的访问控制。如果代码执行是一项预期功能，则服务器不应暴露在公共互联网上，或者应严格限制只有高权限用户才能访问。  
  
这些漏洞主要影响 Calibre 内容服务器功能，这是用于在线共享电子书库的流行工具。虽然受影响用户的确切数量尚不清楚，但 Calibre 的广泛采用（尤其是在狂热读者、学术研究人员和文学爱好者中）放大了这些缺陷的潜在影响。  
  
强烈建议用户立即将软件升级到  
最新版本  
  
，以减轻与这些安全问题相关的风险。此外，在内容服务器上启用基本身份验证可以提供额外的保护层，防止未经授权的访问。  
  
**漏洞详情：**  
  
https://starlabs.sg/advisories/24/24-7008/  
  
https://starlabs.sg/advisories/24/24-6781/  
  
https://starlabs.sg/advisories/24/24-6782/  
  
**软件新版本：**  
  
https://calibre-ebook.com/download  
  
  
