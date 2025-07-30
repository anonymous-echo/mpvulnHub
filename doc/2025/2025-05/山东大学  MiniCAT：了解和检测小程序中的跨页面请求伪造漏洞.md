#  山东大学 | MiniCAT：了解和检测小程序中的跨页面请求伪造漏洞   
原创 李智宇  安全学术圈   2025-05-19 04:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEmQgOI3vhpicia2CXAswSgib5es6FOsLIMTRuHDNQw1HfDZP3uleR8YwEkubVzFWibmaLeUdgXiavZABQ/640?wx_fmt=png&from=appmsg "")  
> 原文标题：MiniCAT: Understanding and Detecting Cross-Page Request Forgery Vulnerabilities in Mini-Programs  
原文作者：Zidong Zhang，Qinsheng Hou，Lingyun Ying， Wenrui Diao， Yacong Gu， Rui Li， Shanqing Guo，Haixin Duan  
原文链接：https://doi.org/10.1145/3658644.3670294  
发表会议：CCS  
笔记作者：李智宇@安全学术圈  
主编：黄诚@安全学术圈  
编辑：张贝宁@安全学术圈  
  
### 1、引言  
  
小程序是运行在超级应用（如微信、百度、支付宝和抖音）中的轻量级应用并在全球范围内普及。研究者发现了一种称为 MiniCPRF 的新型小程序漏洞，该漏洞源于小程序中页面路由和用户状态管理的设计缺陷并会造成如下后果：  
- 诱导受害者访问被篡改的小程序页面路由，从而执行敏感操作。  
  
- 从小程序路由中窃取敏感信息。  
  
为了评估 MiniCPRF 的影响，本文提出了一个名为 MiniCAT 的自动化分析框架。它可以自动爬取小程序，对其进行静态分析，并生成检测报告。通过使用 MiniCAT 进行的大规模真实评估发现：32.0% 的微信小程序可能存在 MiniCPRF 漏洞，其中包括拥有数百万用户的搜狐和问卷星。  
### 2、背景介绍  
  
在本文提出的威胁模型中，攻击者与受害者均为普通微信用户，攻击者通过伪造或篡改微信小程序卡片实施攻击，不直接拦截通信或控制受害设备，也不对受害者的设备进行物理或远程操控。攻击者可以直接或间接地从受害者处获得页面路由 URL 和相应的参数，然后生成恶意小程序卡片并诱导受害者点击，从而达成个体或群体攻击目的。由于微信小程序卡片存储在本地，攻击者实现这些功能相对容易。  
  
下图展示了微信小程序的架构以及其如何在渲染层和逻辑层之间实现通信。用户操作通过事件从渲染层传输到逻辑层，以便超级应用程序进行进一步处理。当渲染层活动触发事件时，逻辑层将执行事件处理函数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEmQgOI3vhpicia2CXAswSgib5qq3NYIK0gsQ3cUquRMlKjmoR9WOoqKmJwmHMMzcK22U4kwGbNqEMLQ/640?wx_fmt=png&from=appmsg "")  
  
利用 MiniCPRF 的完整攻击流程可以概括为三个步骤：  
- 攻击者识别潜在的易受攻击页面，并通过转发从页面的路由 URL 中获取参数。  
  
- 攻击者修改小程序卡片或通过修改页面路由 URL 生成新的小程序卡片。  
  
- 当受害者或某些攻击者点击小程序卡片时，攻击者可以执行敏感操作。  
  
导致 MiniCPRF 出现的三大主要因素如下：  
- 微信小程序路由仅允许开发者在 URL 模式中传递参数。如果开发者在页面路由 URL 中以明文形式传输敏感参数，可能会导致信息泄露以及相关的安全风险。  
  
- 微信小程序缺乏统一和整体的用户状态验证，现有的用户状态安全取决于开发者的意识。  
  
- 微信缺乏完整性检查，导致修改和伪造的恶意小程序卡片可以被转发。攻击者可以轻松访问并查看和修改以纯文本 XML 格式存储在本地的卡片中的页面路由参数。  
  
### 3、方案设计  
  
如下图所示，MiniCAT 包含两个模块：  
- 小程序爬虫，用于收集大量小程序。其利用自然语言处理（NLP）技术以及小程序元数据构建关键词词典，在微信 Windows 客户端内搜索小程序。该爬虫程序从用户配置文件目录中检索小程序包，将其解包为源代码后作为 MiniCPRF 检测器的输入。  
  
- MiniCPRF 检测器，用于检测小程序中的 MiniCPRF 漏洞。其设计步骤如下：  
  
- 识别调用页面路由 API 的节点。MiniCPRF 检测器首先解析微信小程序的 JavaScript 代码，构建抽象语法树（AST）以筛选出调用这些 API 的节点，然后提取其 url 属性值，利用正则表达式将通过页面路由 API 传递的 URL 拆分为目标页面路由和参数。  
  
- 构建攻击路径。在获取了小程序页面的路由和参数后，MiniCPRF 检测器利用一种基于反向污点分析的方法以自动化分析攻击路径。该方法通过定义每个节点的前置节点（PR节点）范围，实现对事件处理函数的精确定位，然后实现基于 WXML 文件的数据流分析。  
  
- 检查用户状态。MiniCPRF 检测器通过静态分析检测易受攻击页面加载函数中两类 API 调用的缺失情况：用户状态检查 API 用于验证状态是否过期；本地存储读取 API 用于获取缓存中的用户凭证。缺少此类调用表明页面在加载时未检查用户状态，从而导致安全风险。  
  
- 可分享性检查。MiniCPRF 检测器分析第一步中带有页面路由 API 调用的页面，检查其是否使用 onShareAppMessage 函数来确定其可分享性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEmQgOI3vhpicia2CXAswSgib5qia7T5NUQjL1rrNRNhX0bn86YyZD3smiaJY9Z2Y0DCEbBOTD6tA7D0pA/640?wx_fmt=png&from=appmsg "")  
### 4、实验评估  
  
小程序爬虫收集并成功解包了 44,273 个微信小程序，包含 2,264,377 个页面。MiniCAT 成功分析了 41,726 个，并识别出 13,349 个小程序可能存在漏洞，119,471 个页面存在风险。在 13,349个小程序中，有 503 个（3.8%）匹配了易受攻击的小程序模板，有 106,362 个（89.0%）页面不涉及用户状态检查。  
  
由下图可知：在所有受 MiniCPRF 影响的小程序类别中，生活方式类占比最高（25.7%），政务类（18.4%）和金融类（7.2%）的比例也相对较高。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEmQgOI3vhpicia2CXAswSgib59VyRgRxFLspoosPial1JZMqfMKCiaA2qh6DibFWSjq32HPJ2sIQvWvtrA/640?wx_fmt=png&from=appmsg "")  
  
通过分析七天内 3,208 个微信小程序及其 9,007 个关联域名的 pDNS 记录，发现许多易受攻击的小程序拥有较高的访问量。下表展示了按 pDNS 记录计数排名的前 10 个小程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEmQgOI3vhpicia2CXAswSgib57ZC1e5IYoXgBXA8TTw1G2cjodia0cAdTdMF3ByIwKT6TsYRTkZrUpQg/640?wx_fmt=png&from=appmsg "")  
  
研究者将与潜在漏洞相关的参数分为五类：支付信息、促销信息、订单信息、设备信息、个人信息。该实验从每个类别中随机选择 80 个小程序，MiniCAT 在 316(79.0%) 个小程序中检测到严重的安全问题，其中又有 234 个小程序存在敏感信息泄露，82 个小程序可以执行越权敏感操作。下表展示了 13,349 个易受攻击小程序的分类结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEmQgOI3vhpicia2CXAswSgib5YwSLzf4wOEFo1KpfCbzz39tjKlU2JU1W3EO9LYtFicNeV229VrdFCdw/640?wx_fmt=png&from=appmsg "")  
  
此外，通过分析多平台同名小程序发现：企业微信有 49/49（100%）、百度有 47/49（95.9%）、支付宝有 20/23（87.0%）和抖音有 12/17（71.5%）的小程序均表现出与微信相似的漏洞模式。产生不一致结果的原因是路由前缀不同，表明该漏洞具有跨平台普遍性。下图展示了问卷星小程序在不同平台上参数和目标页面的的相似性：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6Dibw6L070WEmQgOI3vhpicia2CXAswSgib5STF9Uib7iaQPDvrwVslLhhM2zDbeAheWF6HNBa1jDVTDzdBdRQ6dhOUQ/640?wx_fmt=png&from=appmsg "")  
### 5、总结  
  
本文提出了一种新型小程序漏洞 MiniCPRF，其根源在于小程序框架的页面路由与用户状态管理的设计缺陷。通过开发自动化工具 MiniCAT 对 41,726 个小程序的分析，发现 13,349 个小程序具有潜在的 MiniCPRF 漏洞，并结合 pDNS 与多平台评估，证实 MiniCPRF 对小程序生态构成实际威胁，且大多数开发者尚未意识到其存在。  
  
> [安全学术圈招募队友-ing](http://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247484475&idx=1&sn=2c91c6a161d1c5bc3b424de3bccaaee0&chksm=fe2efbb0c95972a67513c3340c98e20c752ca06d8575838c1af65fc2d6ddebd7f486aa75f6c3&scene=21#wechat_redirect)  
   
  
有兴趣加入学术圈的请联系   
**secdr#qq.com**  
  
  
**专题最新征文**  
- [期刊征文 | 暗网抑制前沿进展](https://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247491610&idx=1&sn=8b6c9caf92435cbd9b76b77686619972&scene=21#wechat_redirect)  
 (中文核心)  
  
- [期刊征文 | 网络攻击分析与研判](https://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247491661&idx=1&sn=ab0a97741cdf854757ef3024b03f1d44&scene=21#wechat_redirect)  
   
(CCF T2)  
  
- [期刊征文 | 域名安全评估与风险预警](https://mp.weixin.qq.com/s?__biz=MzU5MTM5MTQ2MA==&mid=2247491703&idx=1&sn=7f351031fc81e1b63d5215ddb8dc91b5&scene=21#wechat_redirect)  
   
(CCF T2)  
  
  
  
