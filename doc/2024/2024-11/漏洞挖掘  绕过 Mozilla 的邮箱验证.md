#  漏洞挖掘 | 绕过 Mozilla 的邮箱验证   
白帽子左一  白帽子左一   2024-11-26 04:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
分享一个在 Mozilla 的某款产品中的有趣业务逻辑漏洞。  
## 应用的工作原理  
  
首先，让我快速介绍一下该应用的工作原理。  
  
**Mozilla Monitor** 旨在帮助用户了解数据泄露情况。用户可以使用邮箱注册该服务，以便在他们的凭据在任何已知的泄露事件中被曝光时收到提醒。它通过扫描大量泄露数据的数据库并与用户邮箱进行交叉对比，从而通知用户其信息是否被暴露。  
## 架构  
  
从架构上看，该应用的数据泄露信息由 **haveibeenpwned.com** 提供支持。在此基础上，我们的重点将转向识别和解决特定的逻辑漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnBwLHSh18SGksyntadPXOdy44K11XXAjVOE3VTMcg3Gq99kRtAA1yNg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**主要功能** 如前所述，该应用的核心功能是为监控添加电子邮件地址。在免费试用中，每个 Mozilla 账户最多可以添加五个邮箱。  
  
例如，假设你添加了一个邮箱地址（如   
moraa@gmail.com），系统会向该邮箱发送**验证令牌**。需要确认该令牌后，监控功能才能激活。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tn3YB4tAvoOodLIiaIJlRo4CSRaTOWZWZLKnoA90RkFAtkRRQPGbickmgw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnOjuwHVqHiaFo9icYSuQaiafyIs8vJgHvSGrI6POEfO4y5AxklLExwyyMw/640?wx_fmt=png&from=appmsg "null")  
  
img  
# 深入研究 Mozilla 的 Monitor 产品  
  
我首先检查了响应中是否有任何泄露的验证令牌，但该部分的处理非常到位。接着，我尝试通过各种技巧来操纵发送到服务器的请求。例如，我尝试在同一个请求中添加多个邮箱地址，希望触发错误或发现潜在的漏洞。我还测试了竞争条件，通过在一个连接中发送多个邮箱，查看服务器是否会错误处理请求或将相同的验证令牌发送到不同的邮箱。然而，服务器再一次表现得毫无破绽。  
  
还有一个问题！**验证令牌**长度太长，无法被猜测或通过暴力破解解决。例如，一个像 8034a6f3-cecd-49a4-9c43-2cf5976380a1 这样的令牌几乎不可能破解。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnkicZN6v6VR5iaj7iaRHBsj7hDxUVApvXbY0EDh5aTOkwZ6JTJibcglibicsA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
没有验证令牌，对我们黑客来说真是个麻烦事 :))  
## 源代码审查  
  
幸运的是，Mozilla 的产品是开源的。所以，我决定深入研究该产品 https://github.com/mozilla/blurts-server的开源代码，并花时间仔细审查。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnLjKM2H7AF38fkKdmOibkhPAWcpMgDicEht9Vwddh7gyKiaF3YaEzFSaiag/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我很幸运地发现了一个可以检索账户中所有添加邮箱的接口 **/api/v1/user/breaches**，同时还可以获取每个已验证邮箱关联的数据泄露信息。这是一个绝妙的发现！现在，让我们进一步探索它的功能，以便更好地理解。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnm3ibiaLEtwDFJFsnh2ZKTexaia5XrwoOsPBCUMONZtEbV09ZOMRrAWAqg/640?wx_fmt=png&from=appmsg "null")  
  
img  
## getAllEmailsAndBreaches 函数的详细说明  
  
通过搜索 getAllEmailsAndBreaches 函数，我发现该函数不仅检索已验证邮箱的数据，还会返回未验证邮箱的信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnG3N6oOrNMiaB6Ogo6S17kffbH9FjyWVdWDwibvlNq7ic1KYjVN4HlvP6A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
getAllEmailsAndBreaches 函数的设计目的是收集并返回与用户关联的邮箱地址及这些邮箱相关的数据泄露信息。以下是该函数的工作方式以及它在处理已验证和未验证邮箱方面的影响：  
  
**函数定义和参数**  
  
该函数接受两个参数：  
  
1.**user**：包含关于用户及其关联邮箱地址的信息。  
  
2.**allBreaches**：一个从数据库中获取的数据泄露记录数组。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnHaMJYhMuPLGib6C043Ba2u78oQDkwMYbGyMDUl4a8Kk5Q88IpSGaYCw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**数组初始化**：  
  
初始化了两个数组来存储**已验证和未验证的电子邮件**。verifiedEmails 数组将存储已确认有效的电子邮件，而 unverifiedEmails 数组则存储尚未验证的电子邮件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnh1Mu80Yz1I2Q1guibicMypeGCLyKPOEibIl8yedYIx1WntHDrOApmhibkg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**错误处理**：  
  
该函数包含错误处理机制，以确保用户对象和泄露列表是有效的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnBvhjHJiaD7JK304yJFhsCXZ7MSo5FrJtrRQqz84wibiacPcicnqYIzLnaA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**检索用户电子邮件**：  
  
这一行调用 getUserEmails 函数，从数据库中获取与用户关联的所有电子邮件地址。需要注意的是，这可能包括已验证和未验证的电子邮件 :))  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnnMYyicibJRE8vaR0996YKZc3b8JxB7MYnejxiaY2BSlpnKKrMmMW0PcZA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**处理已验证和未验证的电子邮件**：  
  
用户在 **accounts.firefox.com** 上的主要电子邮件始终首先进行处理，并被打包到 verifiedEmails 数组中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnE4kpiczctuDMQdwsrY4WRYxCKMTEXTiagZtNP7KYuZd93UdLucHicsic3Q/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
接下来，函数遍历 monitoredEmails。对于每个电子邮件，如果它被标记为已验证，则将其打包到 verifiedEmails 数组中。如果电子邮件未验证，则将其添加到 unverifiedEmails 数组中：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnogxfQNrH4D6s3vpW8mPsDfj65tGUTqP8WaFibcmiaNmwfTvHibTF4e4zw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**返回数据**：  
  
在函数的末尾，已验证和未验证的电子邮件作为对象的一部分返回。这意味着该函数暴露了未验证电子邮件的信息，如果处理不当，可能会导致安全隐患。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnQlVSepPDTxIVOBycPXYwCRKGaRuTiaabccKrXHGicUwZPEmgg2CkwGvw/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 验证令牌在响应中泄露  
  
如我们所见，**未验证电子邮件返回的数据没有经过验证**。当我访问这个端点时，发现未验证电子邮件的响应中泄露了验证令牌！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnbwbI5VaeJbcpIibeBYhAnMJg3Of9WgOlyIW5uAQhaplomHhWylFLv0g/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 验证电子邮件端点  
  
我能够抓取到验证令牌，并将其用于验证电子邮件端点来确认电子邮件。现在，由于这个配置错误，我可以轻松地监控任何我想要的电子邮件，而不需要电子邮件所有者的权限 :))  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnQpibgR41a92En3BfesvAUpS37ykINzeCVBrEP4LKWkg08tRH8lOdpIQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tn2ibiblOIznzSfUfibvIYl6m25IficXu2409e3htHR059hhiaAsQT6xwhyug/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
电子邮件已经通过验证，现在可以监控它了 :))  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tn5uSkpnEiaWsRBQjBUz9d5Sw6Gvl8NAF4pInUayXaUxoSskpFicHykCkA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
通过移除未使用的 API 端点 **/user/breaches** API GET 端点修复了漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSEXZcl4KCI6HwHVmR7c56tnhHabjr7GIa87bTGCec0QDX85IYIC3HwUCmXiaUy2j5mvM81Vy5Qp0GA/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 结论  
  
总之，Mozilla Monitor 产品中的这个漏洞突显了彻底测试业务逻辑和访问控制的重要性。通过源代码审查，我发现了一个函数中的缺陷，使我能够绕过电子邮件验证，这展示了即使是小小的疏忽也可能导致重大的安全风险。Mozilla 迅速回应并解决了这个问题，体现了他们对用户安全的强烈承诺。我希望这篇总结能强调细致的代码分析和强有力的安全测试在识别和缓解此类漏洞中的价值。  
  
以上内容由白帽子左一  
翻译并整理。  
原文：https://0d-amr.medium.com/bypass-email-verification-in-mozilla-2ab45ac36c42  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
