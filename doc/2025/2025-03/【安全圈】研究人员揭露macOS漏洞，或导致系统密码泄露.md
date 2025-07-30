#  【安全圈】研究人员揭露macOS漏洞，或导致系统密码泄露   
 安全圈   2025-03-24 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgYLYnTQo8hgmHziathN2gdYnXJBjkdaZOLFHNOJj8iaAuZGvDPiaPsWMLGCSDticKs7ib0HmA2qsbMINQ/640?wx_fmt=png&from=appmsg "")  
  
近期，一个影响macOS系统的严重漏洞被曝光，引发了网络安全专家和用户的广泛关注。该漏洞可能导致敏感的系统密码泄露，并在最新发布的报告中被详细分析和记录。  
### 漏洞背景  
  
该漏洞涉及macOS对系统凭证的处理方式，使得恶意攻击者能够通过直接访问操作系统来利用受保护的数据。这一发现进一步加剧了围绕macOS的安全隐患，凸显了在现代计算环境中加强警惕和安全措施的必要性。  
### 漏洞分析  
  
WTS.Dev的分析师诺亚·格雷戈里（Noah Gregory）是该漏洞的主要发现者，他指出漏洞存在于macOS的钥匙串（Keychain）机制中。钥匙串是macOS负责安全存储系统密码和敏感凭证的组件。格雷戈里解释称，该漏洞可能允许未经授权的用户或应用程序绕过现有的安全协议，从而在无需用户同意或身份验证的情况下从钥匙串中提取数据。如果被利用，这一能力可能导致广泛的破坏，例如侵犯隐私、窃取敏感数据或在macOS环境中升级恶意活动。  
### 技术细节  
  
该漏洞的技术根源在于macOS钥匙串子系统中权限实现的缺陷。格雷戈里的报告指出，尽管理论上只有经过授权的进程才能访问钥匙串，但在某些情况下，未经授权的脚本可以查询并检索存储的密码。研究团队提供的演示表明，恶意代码可以绕过安全检查，从而访问本应受macOS安全层级保护的凭证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgYLYnTQo8hgmHziathN2gdYPxWeZHOiaEWPOQjh0nn6kLtZUeJ20Dib3l0QHoAoVbMnouCwFqkRxiaiaQ/640?wx_fmt=png&from=appmsg "")  
### 漏洞利用示例  
  
格雷戈里及其团队进一步剖析了漏洞，揭示了触发该漏洞的确切条件，并展示了一个示例利用代码，以说明攻击者如何利用这一弱点。以下是用于初步概念验证（PoC）的代码片段：  
```
import Security

let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecReturnAttributes as String: true,
    kSecReturnData as String: true,
    kSecMatchLimit as String: kSecMatchLimitAll
]

var result: AnyObject?
let status = SecItemCopyMatching(query as CFDictionary, &result)

if status == errSecSuccess {
    print("Retrieved password data: \(result)")
} else {
    print("Failed to retrieve data!")
}
```  
```
```  
###   
  
苹果公司已承认该漏洞，并预计在即将发布的macOS更新中通过安全补丁解决这一问题。与此同时，格雷戈里建议用户在官方修复发布之前启用额外的保护层（例如第三方安全工具），以降低漏洞被利用的风险。  
  
来源：https://cybersecuritynews.com/researchers-details-macos-vulnerability/  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】百元秒取照片，千元任查隐私！普通人的信息在这场“人肉开盒“饕餮盛宴中沦为牺牲品](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068670&idx=1&sn=9ea92c6886f94f756c1643f786bc13b5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】俄罗斯零日漏洞卖家开价 400 万美元出售全链 Telegram 漏洞经过 古鲁巴兰- 2025 年 3 月 21 日](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068670&idx=2&sn=4baddc750849fe08ccb334318a0ebcd0&scene=21#wechat_redirect)  
  
  
  
[【安全圈】黑客声称从 Oracle 云服务器窃取了 600 万条销售记录](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068670&idx=3&sn=9241bbcfa7aea0834cabe8acdf58a85e&scene=21#wechat_redirect)  
  
  
  
[【安全圈】长城汽车 App 崩溃，车主被“罚站” 官方致歉](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068645&idx=1&sn=3bfe77bb604a27a3e8b24bef625fe9a5&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
