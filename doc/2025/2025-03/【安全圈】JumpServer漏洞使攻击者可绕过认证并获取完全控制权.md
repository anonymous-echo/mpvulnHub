#  【安全圈】JumpServer漏洞使攻击者可绕过认证并获取完全控制权   
 安全圈   2025-03-24 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgYLYnTQo8hgmHziathN2gdY6m7Yp7BVGGKomdeMyWrAfwIEuWLz0IlODOCgy0SQt4yQhQDmy2UgTg/640?wx_fmt=png&from=appmsg "")  
  
Fit2Cloud 开发的开源特权访问管理 (PAM) 工具 JumpServer 中发现一系列严重漏洞，引发了重大的安全担忧。  
  
JumpServer 作为内部网络的堡垒主机，通过用户友好的 Web 界面提供通过 SSH、RDP、数据库和 FTP 隧道访问内部资源的集中点。  
  
发现的缺陷可能允许未经身份验证的攻击者绕过身份验证并完全控制 JumpServer 基础设施。  
  
Sonar 研究人员发现多个身份验证绕过漏洞（CVE-2023-43650、CVE-2023-43652、CVE-2023-42818、CVE-2023-46123），这些漏洞可能允许攻击者冒充合法用户。  
  
JumpServer 的集中式特性使这些漏洞特别危险，因为破坏该系统可能使攻击者能够访问组织的整个内部网络。  
  
这些漏洞源于架构错误，特别是微服务隔离不足。  
  
JumpServer 的架构由几个组件组成，包括核心 API（用 Python-Django 编写）、数据库、Koko（用 Go 开发，用于隧道功能）、Celery（任务管理器）和作为基于 Web 的连接的入口点的 Web 代理。  
  
一个关键问题是，公钥认证系统缺乏对请求是否来自授权 Koko 服务的验证。如易受攻击的代码所示：  
```
def authenticate(self, request, username=None, public_key=None, **kwargs): प
    if not public_key:
        return None
    if username is None:
        username = kwargs.get(UserModel.USERNAME_FIELD)
    try:
        user = UserModel._default_manager.get_by_natural_key(username)
    except UserModel.DoesNotExist:
        return None
    else:
        if user.check_public_key(public_key) and \
                self.user_can_authenticate(user):
                return user
```  
  
```
```  
  
这使得攻击者可以直接通过 HTTP 接口执行相同的请求，有效地冒充 Koko 容器而无需密钥验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgYLYnTQo8hgmHziathN2gdYIpV9vD6e8EBAo8EmyafQxfY5FvXf4NNeeEicZbO5cTuQYjN50R67Uhw/640?wx_fmt=png&from=appmsg "")  
```
```  
  
由于 SSH 上下文中双因素身份验证的实施存在缺陷，即使启用了MFA的帐户也容易受到攻击，攻击者可以操纵“remote_addr”参数来绕过速率限制机制。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgYLYnTQo8hgmHziathN2gdYwosmoZYlOBGRzbqLBy4M3THlw6FvcntAicKfxlrB5OzroA6mdqEl06A/640?wx_fmt=png&from=appmsg "")  
  
JumpServer 版本 3.10.12 和 4.0.0 已修复该漏洞。使用 JumpServer 的组织应立即更新至这些已修补的版本。  
  
修复包括将公钥认证 API 与令牌生成分开，引入认证的状态跟踪机制，以及为 remote_addr 参数实现基于签名的验证系统。这些漏洞凸显了安全编码实践、全面测试和持续安全评估的重要性，尤其是在作为敏感资源网关的系统中。  
  
来源：https://cybersecuritynews.com/jumpserver-vulnerabilities-let-attacker-bypass-authentication/  
  
  
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
  
  
