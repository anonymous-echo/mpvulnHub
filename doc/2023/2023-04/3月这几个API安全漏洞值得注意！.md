#  3月这几个API安全漏洞值得注意！   
 星阑科技   2023-04-04 14:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOeiaFHTFtiatmEIxZQcXOHfyr6GOBM88IeMm28ybjSAHEJKicuQxPxN5L5NFZ5mza2NOnuokf9ant2fUQ/640?wx_fmt=gif "")  
  
为了让大家的API更加安全  
  
致力于守护数字世界每一次网络调用  
  
小阑公司 PortalLab实验室的同事们  
  
给大家整理了  
  
3月份的一些API安全漏洞报告  
  
希望大家查漏补缺  
  
及时修复自己API可能出现的漏洞  
  
  
No.1  
  
  
**影子API将带来不可预知的漏洞**  
  
  
**漏洞详情：**时至今日，许多企业没有准确的API库存清单，因此导致了一种新的威胁形式，即“影子API”。拥有成熟API开发流程的企业会保存一个API库存清单的资产目录，理想状态下会包含所有可用的API端点信息、可接受参数的细节、认证和授权信息等。然而，许多企业由于没有API库存清单，生产中的API和受益于持续开发的API将会偏离于它们在清单中的原始定义。在这两种情况下都会出现组织不可见的公开API，这些API被称为“影子API”，而许多应用会通过“影子API”被攻破，而企业对这些API了解甚少，甚至毫无察觉。  
  
**漏洞危害：**影子API代表了一种日益增长的风险，可能会导致大规模数据泄露，而受到侵害的组织甚至不知道这种风险的存在。  
  
**影响范围**：通过多种方式利用影子API，可用于访问敏感数据，还可用于造成拒绝服务攻击或欺诈性地向客户收费。  
  
  
  
**小阑修复建议**  
  
**•**采用API标准，这会导致最小的API异常。遵守这些通用标准可以让开发人员尽可能地减少问题。  
  
**•**通过在早期阶段自动化API文档，开发人员可以轻松地节省在手动文档方面投入的大量精力。在CI/CD流程的帮助下，可以合并API文档更新。  
  
**•**在新的API版本发布之前，API安全专家应对遗留API进行安全审核，这样做有助于评估新版本中不可预见的安全风险。  
  
**•** 持续的API库存监控有助于开发人员消除影子API的可能性。  
  
  
No.2  
  
  
**乐高市场用户数据中的API漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOeg8MFonn9D47OKDlN57ibMtxBAQUbZym4gmaYp1vUd3wLnwJ5koz0icM7X1gicwibWsteFm1Gn4SKxPPg/640?wx_fmt=png "")  
  
**漏洞详情：**Salt研究人员发现乐高（LEGO）的线上服务存在安全漏洞，不只可能让攻击者取得其他人账户完全控制权，还泄露PII以及敏感资料，同时攻击者也能够访问内部资料，而这可能导致内部服务器遭入侵。  
  
**漏洞危害：**bricklink.com中两个API安全漏洞，第一个漏洞是发生在用户输入字段，在优惠券搜索的寻找用户名对话框中，存在一个跨站脚本（XSS）漏洞，攻击者能够设计连接，在终端用户的计算机上注入和执行程序代码，只要运用暴露在不同页面上的Session ID，连接跨站脚本，便能劫持Session并且接管账户。  
  
第二个漏洞则是在上传至愿望清单页面，这页面让用户能够以XML格式上传想要的零件列表，而攻击者在这个页面便能够进行XML外部实体攻击（XEE），读取网页服务器上的文件，并以服务器端请求伪造（Server-side request forgery）来访问并且操作无法被直接访问的资讯，包括AWS EC2权限。  
  
**影响范围：**乐高线上市场存在的两个严重漏洞，可泄露用户个人信息与服务器机密资讯。  
  
  
  
**小阑修复建议**  
  
**•**避免XSS的方法之一主要是将用户所提供的内容输入输出进行过滤，许多语言都有提供对HTML的过滤。  
  
**•**过滤输入的数据，对例如：“ ‘ ”，“ “ ”，” < “，” > “，” on* “，script、iframe等危险字符进行严格的检查。这里的输入不仅仅是用户可以直接交互的输入接口，也包括HTTP请求中的Cookie中的变量，HTTP请求头部中的变量等。  
  
**•**对输出到页面的数据进行相应的编码转换，如HTML实体编码、JS编码等。  
  
**•**避免XEE的方法是先检查所使用的底层XML解析库，默认禁止外部实体的解析。  
  
**•**若使用第三方应用代码，需要及时升级补丁。  
  
**•**对用户提交的XML数据进行过滤，如关键词：<!DOCTYPE和<!ENTITY或者SYSTEM和PUBLIC等。  
  
  
No.3  
  
  
**IBM WebSphere Application Server 代码注入漏洞**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOeg8MFonn9D47OKDlN57ibMtxYzBDRKicYm0S8eDdF5d7ibW2ATD6uOgFNOSyBasw13pf1bhW4xLx0zYQ/640?wx_fmt=png "")  
  
  
**漏洞详情：**WebSphere Application Server是企业级Web中间件，由于其可靠、灵活和健壮的特点，被广泛应用于企业的Web服务中。该漏洞编号为：CVE-2023-23477（CNNVD编号：CNNVD-202302-119）。成功利用此漏洞的攻击者，最终可远程在目标系统上执行任意代码。  
  
**漏洞危害**：IBM WebSphere Application Server（WAS）是美国国际商业机器（IBM）公司的一款应用服务器产品。该产品是JavaEE和Web服务应用程序的平台，也是IBM WebSphere软件平台的基础。由于WebSphere Application Server对用户输入数据的验证存在缺陷，在特定条件下，未经身份验证的远程攻击者通过构造恶意的序列化数据，可实现在目标服务器上任意执行代码。  
  
**影响范围：**CVSS评分为8.1，受影响版本：  
  
**•** 5.0.0 <= WebSphere Application Server <= v8.5.5.19  
  
**•** 0.0.0 <= WebSphere Application Server <= v9.0.5.7  
  
  
  
**小阑修复建议**  
  
**•** 目前官方已发布更新修复了该漏洞，请受影响的用户尽快安装进行防护。  
  
**•****下载地址：**https://www.ibm.com/support/pages/recommended-updates-websphere-application-server  
  
  
No.4  
  
  
**Smartbi 远程命令执行漏洞**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOeg8MFonn9D47OKDlN57ibMtxYvvhU4fZTxKotaj3PqFVTy2EcEPROKwKBpQeZ6MSFUNFaGU1TjerlA/640?wx_fmt=png "")  
  
  
**漏洞详情：**Smartbi远程命令执行漏洞，漏洞编号暂无。攻击者可以通过利用路由匹配结合 JNDI 注入进行任意命令执行，导致系统被攻击与控制。利用此漏洞的攻击者，最终可远程在目标系统上执行任意命令。  
  
**漏洞危害：**Smartbi是思迈特软件推出的商业智能BI软件，满足BI产品的发展阶段。思迈特软件整合了各行业的数据分析和决策支持的功能需求，满足最终用户在企业级报表、数据可视化分析、自助探索分析、数据挖掘建模、AI 智能分析等场景的大数据分析需求。Smartbi大数据分析平台存在远程命令执行漏洞，未经身份认证的远程攻击者可利用stub接口构造请求绕过补丁限制，进而控制JDBC URL，最终可导致远程代码执行或信息泄露。  
  
**影响范围：**  
  
**•** 威胁等级：高危；  
  
**•** 影响面：高；  
  
**•** 攻击者价值：高；  
  
**•** 利用难度：低；  
  
**•** 漏洞评分：9.8；  
  
**•** 影响版本：v7 <= Smartbi <= v10.5.8  
  
  
  
**小阑修复建议**  
  
**•** 缓解措施：配置 WAF 规则，对数据包中有 clientRerouteServerListJNDIName 关键字数据包过滤。  
  
**•** 官方已发布漏洞补丁及修复版本，请评估业务是否受影响后，酌情升级至安全版本。  
  
**•** 小阑建议您在升级前做好数据备份工作，避免出现意外。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOeg8MFonn9D47OKDlN57ibMtxhgFE4Obp0q1Qm0GtZKKp9CPCcHRia2ezhyz6QeCqib34cZasbJkJxenQ/640?wx_fmt=png "")  
  
  
星阑科技“萤火”API安全分析平台可以支持多种API漏洞的检测。有相关需求的可以在公众号进行留言，或添加“小阑本阑”客服微信进行咨询。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOeg8MFonn9D47OKDlN57ibMtxpLWpXppbTeROuVCvsdUJqFppYT62qPRepVRKvOTkMIjxxPF5U68jjA/640?wx_fmt=jpeg "")  
  
（长按或扫描图中二维码即可添加）  
  
  
  
**关于Portal Lab 实验室**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Cc8QqLUKOeg8MFonn9D47OKDlN57ibMtxPcbO2QGGPiajBHp4gbma6EqqUrJCXgKibPBMjlPksFFmXGa2teYz1Mnw/640?wx_fmt=png "")  
  
  
星阑科技 Portal Lab 致力于前沿安全技术研究及能力工具化。主要研究方向为API 安全、应用安全、攻防对抗等领域。实验室成员研究成果曾发表于BlackHat、HITB、BlueHat、KCon、XCon等国内外知名安全会议，并多次发布开源安全工具。未来，Portal Lab将继续以开放创新的态度积极投入各类安全技术研究，持续为安全社区及企业级客户提供高质量技术输出。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Cc8QqLUKOeg8MFonn9D47OKDlN57ibMtxrGmdgQpgA841Yaj5Hib55nC7drwAJyHV9TqiajV0YPInxfS5FLX8SGXQ/640?wx_fmt=jpeg "")  
  
**关注“星阑实验室”公众号**  
  
**了解更多关于API安全的技术知识**  
  
  
  
**往期 · 推荐**  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247497116&idx=1&sn=5c923d8be68f1cd6e25f919a335f1d6d&chksm=c0075800f770d116c4b88a2af42f99df82da76626874b8a3d985397a7d14b13e4cbeb77f0263&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247496967&idx=1&sn=365faa1f815f59f9614f8dfa3e3854c3&chksm=c007589bf770d18da031d6d11f97adfa9a6c354db231f6709c9a33725f015adef720920efa89&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247496954&idx=1&sn=720b26c65b4eb7137d92977d080ad371&chksm=c0075966f770d070417cb747fe8269fd7758517e9852a720450c74ec64c2d9b24aa89a32731c&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg5NjEyMjA5OQ==&mid=2247496905&idx=1&sn=26919ff4d1ad952d8513fc7fecfa4fe5&chksm=c0075955f770d043f4150c3aa4caaa77caa692ea72ea56556d388bdde0c1c1e4ab5279329ba0&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Cc8QqLUKOehwcHoxicoOah5mxDjLHMZ9RHUxNeibERphRXOj3AEupxt7JyOt3LF1RmmWQibYmicTv2DxM93iaEJhLxw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
