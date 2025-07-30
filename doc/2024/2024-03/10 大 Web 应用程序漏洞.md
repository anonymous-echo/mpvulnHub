#  10 大 Web 应用程序漏洞   
点击关注👉  马哥网络安全   2024-03-28 12:01  
  
为了帮助公司应对 Web 应用程序漏洞并保护自己的 Web 应用程序，开放 Web 应用程序安全项目 (OWASP) 在线社区创建了 OWASP 前十排行榜。当我们跟踪他们的排名时，我们注意到我们对主要漏洞的排名方式有所不同。出于好奇，我们决定找出差异到底有多大。这就是为什么我们建立了自己的排名，该排名反映了我们通过八年经验对最广泛和最关键的 Web 应用程序漏洞的看法。  
  
  
参与者简介和申请  
  
  
  
  
我们从我们团队在 2021-2023 年完成的应用程序安全评估项目样本中收集了数据。大多数网络应用程序由俄罗斯、中国和中东的公司拥有。  
  
几乎一半的应用程序 (44%) 是用 Java 编写的，其次是 NodeJS (17%) 和 PHP (12%)。超过三分之一 (39%) 使用微服务架构。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MbON44ezWkABaxh6H6yaia8MEOLpKfuicyIxN0c44ibb8iase8Z5x9pGHTA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年编写 Web 应用程序所用编程语言的分布**  
  
  
我们用黑盒、灰盒和白盒方法对 Web 应用程序进行评估获得数据然后进行分析。几乎每个用灰盒评估的应用程序也用黑盒进行分析，因此我们在统计中结合了这两种方法。因此，绝大多数（83％）的Web应用程序项目都使用黑盒和灰盒方法。  
  
**分析方法不同造成的差异**  
  
由于黑盒、灰盒和白盒方法意味着对应用程序的访问级别不同，因此可能发现的漏洞类型也不同。我们比较了访问应用程序源代码和不访问应用程序源代码时发现的漏洞。结果，五个最普遍的漏洞中有四个匹配，但也存在差异。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01M4icGwtxm9bRWEn0CVbviahFmKU8TV69PdeO3kP6jJsuhSWpJBLibhk1YA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**黑/灰和白盒分析中发现的最普遍的漏洞**  
  
  
此外，统计数据显示，白盒方法可以发现更多严重漏洞，例如 SQL 注入。平均而言，黑/灰盒分析发现了 23 个漏洞，白盒分析发现了 30 个漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MBQUb18IDWLo751Gt0w4WooibHgf8coh0mmWZtWnvkI7ebkkib8jD8xAw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年使用黑/灰盒分析平均发现的每个应用程序中不同风险级别的漏洞比例**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MaeEo4b2ibsy19p2cP1iciaR3oic39OtB3iatyXq5E45gTKgHVEQzzoAZQwg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年使用白盒分析平均发现的每个应用程序中不同风险级别的漏洞比例**  
  
  
尽管白盒方法允许为每个应用程序查找更多数量的漏洞，但黑盒和灰盒方法可用于从恶意行为者的角度查看应用程序并识别必须首先修复的漏洞。  
  
  
十大 Web 应用程序漏洞  
  
  
  
  
我们分析了网络应用程序评估项目的结果，以确定数字世界在过去三年中面临的最广泛和最严重的漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MQbLQuhqOoKGS1EmoEMktgwvuC6wDnbgTq4icNvIohicTOBpeuoM6NJuw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
该排名是根据包含特定漏洞的应用程序数量和影响严重程度得出的专家意见。  
  
这些排名中提供的建议本质上是一般性的，并且基于信息安全最佳实践标准和指南，例如 OWASP 和 NIST。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01M3Veiba3Grv4pPwM3Sb9euNvgfrneZLUlvIbiaVdpokBeqVb3SiajiaMNFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**01**  
  
访问控制被破坏  
  
我们分析的 70% 的 Web 应用程序包含与访问控制问题相关的漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MCKKszAbLL3gYhPhx6uhrv6QOKEZibzjAljXyI6PmWFlfRxIqLBW38hg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年损坏的访问控制漏洞按风险级别的分布**  
  
  
近一半的损坏访问控制漏洞具有中等风险级别，37% 具有高风险级别。高危漏洞可能会导致应用程序出现错误并影响客户的业务。在一个应用程序中，由于对提交的数据验证不充分，我们可以访问内部服务并可能执行导致财务损失的攻击  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01Moqbt5RdTy4vshTichDBjicp3OH8OPr7RmKe1NlSgcBpciag9iciaQcCibXiaA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
根据基于角色的访问模型实施身份验证和授权控制。除非资源可供公开访问，否则默认拒绝访问。  
  
**02**  
  
敏感数据暴露  
  
此类漏洞是 Web 应用程序中常见的另一种漏洞。与破坏访问控制相比，敏感数据暴露包含更多的低风险漏洞，但也存在高风险漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01M6dLNLbOF5BSB9jc2MwWwu6DpdWUDBia4IMGkSL0hxA52ujaTfNTxbXQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021 年至 2023 年按风险级别划分的敏感数据泄露漏洞分布**  
  
  
我们在分析过程中发现的敏感数据包括纯文本一次性密码和凭据、Web 应用程序发布目录的完整路径以及可用于了解应用程序架构的其他内部信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MPsWic2HK5ic2eOUdEjrDtiaUyNYhGBUEzW3udfa05iahKIGic9zmcHW7ynw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
不要在 Web 应用程序发布目录中存储包含敏感数据（例如密码或备份）的文件。访问应用程序功能时避免泄露敏感数据，除非该功能本身用于访问敏感数据。  
  
**03**  
  
服务器端请求伪造（SSRF）  
  
云和微服务架构的受欢迎程度正在上升。与传统架构相比，微服务架构扩大了 SSRF 攻击的攻击面，因为更多的服务通过 HTTP（或其他轻量级协议）进行通信。我们分析的超过一半 (57%) 的应用程序包含一个漏洞，该漏洞可让恶意攻击者绕过应用程序逻辑后与内部服务进行通信：服务器端请求伪造。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01Mq9sL4aUWVRoe6aiaFOicAEaHGK3LzfVHPY3W9gtzRQumNzFzjjvSqNcQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年 SSRF 漏洞按风险级别分布**  
  
  
具体来说，恶意行为者可以将 SSRF 与其他漏洞串联起来，对 Web 服务器发起攻击或读取应用程序源代码  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MOOxsdPL0G2oZ3CibHraosGXUJWJ8CP0RTt9N2PhSBOKxxW7vgkrm0Iw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
如果可能，创建应用程序可以请求的资源白名单。阻止对不在该列表中的任何资源的请求。不接受包含完整 URL 的请求。设置防火墙过滤器以防止访问未经授权的域。  
  
**04**  
  
SQL注入  
  
2021-2023 年大多数高风险漏洞都与 SQL 注入相关。尽管如此，我们仍将这一类别排在第四位，因为我们分析的应用程序中只有 43% 容易受到此漏洞的影响。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01M3YzUaTzd6Zj95JAMqL2xmVKLxkJ3dj4MUvjoCib2CXd6aZG509qPiaSg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年按风险级别划分的 SQL 注入漏洞分布**  
  
  
此类漏洞可能导致敏感信息被盗或远程代码执行。在其中一个项目中，对一个可供任何互联网用户注册的应用程序进行 SQL 注入，使我们能够获取内部系统管理员的凭据。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MNYwPxOp1Ygmq5wXDWicBdODjwk7jbVMHf7J8kaelSicwoXso6xILQJqA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
在应用程序源代码中使用参数化 SQL 查询，而不是将它们与 SQL 查询模板结合起来。如果无法使用参数化 SQL 查询，请确保用户输入的用于生成 SQL 查询的数据不能用于修改查询逻辑  
  
**05**  
  
跨站脚本 (XSS)  
  
我们分析的 61% 的 Web 应用程序中发现了跨站脚本漏洞。在大多数情况下，该漏洞具有中等风险级别，因此我们将其排在第五位，尽管它非常普遍。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MnNmpehSM1QzGVtgykYDcFTMaqrV7fTONia33rbiauliceqIXoC54L8l1Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年 XSS 漏洞按风险级别分布**  
  
  
超过一半 (55%) 的 XSS 漏洞与 IT 公司使用的应用程序相关，其次是公共部门 (39%)。  
  
针对应用程序客户端的 XSS 攻击可用于获取用户身份验证信息，例如 cookie、网络钓鱼或传播恶意软件。在一种攻击场景中，XSS 与其他漏洞相结合，允许将用户密码更改为已知值，从而使用该用户的权限获取对应用程序的访问权限。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01Miczg2r0gcriaMDUlbHqOwaNMITPhHuq7lNyOknHT7U07h3yQLUudibX2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
通过将可用于格式化 HTML 页面的潜在不安全字符替换为非格式字符的等效字符，对 Web 应用程序用户输入进行处理。对于从外部源获取并显示在浏览器中的任何数据（包括 HTTP 标头，如 User-Agent 和 Referer），都应该执行此操作。  
  
**06**  
  
身份验证失效  
  
尽管我们在此类别中发现的漏洞中几乎一半具有中等风险级别 (47%)，但也存在高风险漏洞，允许代表客户的客户端访问 Web 应用程序。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01M0RU55c4nOia5d4rjJVzVdvn0GLfqkSEsL72EXniaubuJdVGbReKPqjZA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年按风险级别划分的破坏身份验证漏洞的分布**  
  
  
例如，某个应用程序没有 JWT（Jason Web Token）签名检查，因此恶意行为者可以修改自己的 JWT（通过指定另一个用户的 ID）并使用生成的令牌在帐户内执行各种操作。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01Meibx3jtJ5IjBcbvXpthjTGtGoosHhP3tjsoIL3kP23yunuSHkw0NFyA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
对用于访问应用程序的身份验证数据进行适当的验证。使用时验证令牌和会话 ID 签名。用于身份验证的秘密（加密密钥、签名等）应该是唯一的并且具有高度的熵。不要在应用程序代码中存储机密。  
  
**07**  
  
安全配置错误  
  
我们分析的应用程序中不到一半包含安全配置错误漏洞。此类别涵盖从启用调试模式到禁用身份验证的一系列漏洞。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MzKhSeyyIJiaRwUZ9RtvuUI07Gh1Y5aj76mSASX4te8XvGKNwUn4Ukjw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年按风险级别划分的安全配置错误漏洞分布**  
  
  
我们分析的一个应用程序的 Nginx 服务器允许访问父目录（相对于 Alias 指令中指定的目录）中的文件。这可用于访问包含机密数据的文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MdqIdEFeR6y1eXbX24zLJ5vUSRPibIkkpX5gQrk9DfhvonOHZMNYQrCg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
配置 IT 基础设施中使用的系统时遵循安全最佳实践。自动化设置过程以消除设置新系统时的错误。对测试和生产系统使用不同的凭据。禁用未使用的组件。  
  
**08**  
  
对暴力攻击的防护不足  
  
我们分析的应用程序中有超过三分之一允许暴力攻击。一次性密码和针对各种资源（例如帐户或文件系统）的身份验证是我们发现的一些易受攻击的机制。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01M2e5cszHA37RNjVLTxucxPYiaxoJtyYWHmHSQQG6GLOthibv7OUAwtqfw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年暴力攻击防护不足漏洞的风险级别分布**  
  
  
具体来说，不良的 OTP 实现可能会允许攻击者暴力破解 OTP，绕过此身份验证因素，从而使对应用程序的未经授权的访问变得更加容易。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01Mcia8k8zC0NfIMfgDFGZQ7fQFkAg0lUfc24jH3afS3ka9w1fGp1BLsTQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
使用 CAPTCHA 使攻击者更难暴力破解凭据。您还可以使用预防控制（WAF、IPS）来及时阻止暴力破解尝试，无论是同一帐户多次登录失败还是同一来源的不同帐户多次登录失败。  
  
**09**  
  
弱用户密码  
  
我们分析的 Web 应用程序中有 22% 设置了弱密码。  
  
此类漏洞比例相对较低的一个解释是，安全分析师经常使用客户测试平台而不是实时系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01Mu5ry74C8riarcdb0eochN51oqhSnHhZhudTuBNROGePEzbQ9mCyYjOw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021 年至 2023 年按风险级别划分的弱用户密码漏洞分布**  
  
  
尽管包含此类漏洞的应用程序数量很少，但利用弱凭据的后果可能会很严重。根据帐户类型，攻击者可以访问基本应用程序功能或管理场景，这可能会影响业务流程。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01Mt6zbvsgGqsic24F2xI17ib6Jseqc0oeHSTrGfvNf6IGdpMQBbQlGyR2w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
实施弱密码检查，例如，针对 10,000 个最弱密码的列表运行新的或更改的密码。强制执行密码长度、复杂性和过期要求，以及其他基于证据的现代密码策略。  
  
**10**  
  
使用具有已知漏洞的组件  
  
最后但并非不重要的广泛类别是使用具有已知漏洞的组件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MbnNHVJ0s1KIR5zg2pMkodJRlmrsQBLRMbQO5oO2dibbZdDbBF7laBfg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**2021-2023 年按风险级别划分的使用具有已知漏洞的组件导致的漏洞分布**  
  
  
易受攻击的组件包括框架和各种应用程序依赖项，例如库和模块。其中一些允许我们访问应用程序使用的服务器，从而渗透客户的内部网络。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BscvC1hbNBfeI2aKuvmeia5iakSACaN01MovUfFcvKBaW6y4kAPzibv1pSsiapkdEytILlBndLUxa5KOOicNoCImskw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**缓解措施**  
  
  
  
定期清点您使用的软件组件，并根据需要进行更新。仅使用已成功通过安全测试的可信组件。禁用任何未使用的组件。  
  
  
**结 论**  
  
Conclusions  
  
  
修复本研究中描述的最普遍的 Web 应用程序漏洞将帮助您保护机密数据并避免 Web 应用程序和相关系统受到损害。为了提高Web应用的安全性并及时发现攻击，我们建议您执行以下操作：  
  
• 遵循安全软件开发生命周期(SSDLC)。  
  
• 定期运行应用程序安全评估。  
  
• 使用日志记录和监控来跟踪应用程序活动  
  
  
来源：卡巴斯基，侵删  
  
