#  【海外SRC赏金挖掘】供应链攻击，通过依赖投毒实现RCE（二） -- PyPI   
原创 fkalis  fkalis   2024-09-22 17:36  
  
# 海外SRC赏金挖掘专栏  
> **在学习SRC，漏洞挖掘，外网打点，渗透测试，攻防打点等的过程中，我很喜欢看一些国外的漏洞报告，总能通过国外的赏金大牛，黑客分享中学习到很多东西，有的是一些新的信息收集方式，又或者是一些骚思路,骚姿势，又或者是苛刻环境的漏洞利用。于是我打算开启这个专栏，将我认为优秀的文章进行翻译，加入我的理解和笔记，方便我自己学习和各位师傅共同进步，我争取做到日更，如果各位师傅觉得有用的话，可以给我点个关注~~ 如果师傅们有什么好的建议也欢迎联系我~~ 感谢各位师傅的支持~~**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBicdYMrcDj1IM8qV6I0rkpibO7pTY4CibicHmG6uHuL0eiasl9l6xI2MDRZaKhicsPUAdzslV95G055uvHibw/640?wx_fmt=png&from=appmsg "")  
# 正文部分  
## 声明  
> **本教程只用于学习和研究 Dependency Confusion 漏洞，请不要在没有授权的情况下对网站进行非法测试，请不要进行非法投毒！！！**  
**只有掌握了他的具体实现方式，才能更好的对其进行防护，这需要多方的共同努力，PyPI官方的限制过滤，开发者对删除流行项目的危害性的认知，以及广大使用者的安全意识，知攻善放，共同进步~~**  
  
## 文章参考  
> **本文根据jfrog网站中的文章进行提炼翻译和总结~~**  
  
  
Revival Hijack - PyPI hijack technique exploited in the wild, puts 22K packages at risk[1]  
## PyPI 供应链投毒常见的两种方式  
### 利用拼写错误导致供应链投毒  
> **开源软件存储库用户最常见的攻击媒介之一是****拼写错误****，恶意行为者注册的名称与流行的包略有不同。当目标在安装流行包的时候进行了错误的拼写，则会下载到恶意的包库，导致RCE**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceqIUI0hicZ7Ianyq2iaurvGMJhSL8YakSKvia78Z6r6RJXHhlKfbicxDJ9ibbZ6IK2oUf1zHiaOGjCrF0A/640?wx_fmt=png&from=appmsg "null")  
  
开发人员可能会意外安装这些欺骗性软件包，从而导致潜在的安全漏洞。尽管这种方法曾经有效，但  
现代开发环境已越来越多地减轻了它对人为错误的依赖，从而降低了它在企业环境中的有效性。  
### 抢注被删除的流行包库导致供应链投毒  
> **一旦删除了流行的项目，攻击者就可以轻松劫持相同的包名称，并且创建一个更高版本的包库，随后当用户尝试进行更新的时候，就会导致设备被控制感染**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceqIUI0hicZ7Ianyq2iaurvGMEZ96gicZGAyZribPMicxtCFiczQe2ics6ib7GcZ6IuUsuDt6DXnpUXyfPW1g/640?wx_fmt=png&from=appmsg "null")  
  
目前唯一的保护措施是一个对话框，警告原始开发人员他们行为的潜在后果 -  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBiceqIUI0hicZ7Ianyq2iaurvGMgPMfkpnECrYI00fxOE3LoLKLbmTy4ianElQjKAiaRkQXCAloM8NhGEXw/640?wx_fmt=other&from=appmsg "null")  
  
但是只要开发者进行了删除，他的利用条件就会非常的低，不需要用户因为粗心而拼写错误，而是直接进行流行包库的接管  
#### 补充：为什么流行的软件包甚至会从 PyPI 中删除？基本分为下面几个原因  
1. 1. 将相同的功能引入官方库或内置 API  
  
1. 2. 缺乏维护（维护者无法再正确地支持库）  
  
1. 3. 包由同一开发人员重新编写（类似的功能，新的包）  
  
### 漏洞复现  
> **为了测试 Revival Hijack 攻击的可行性，jfrog以安全的方式复现了**  
  
#### 1. 创建了一个名为 revival-package 版本 1.0.0 的空包，并从 origin_author 帐户发布它。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceqIUI0hicZ7Ianyq2iaurvGMhMwcUZ51ANkWCdWKu9uBgj7v3CPCfaWYj5RHFqm2dp0mbpEiagXWVMA/640?wx_fmt=png&from=appmsg "null")  
  
#### 2. 然后，删除了该项目，并从其他帐户 new_author 使用版本 4.0.0 发布了一个同名的包。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceqIUI0hicZ7Ianyq2iaurvGMkDFNUaCJTmPBn2Ua64hvmYCQicfznxRGpgsTya7OfOubOA3p3pJNZXw/640?wx_fmt=png&from=appmsg "null")  
  
**可以看见属于原始用户的版本已被完全删除，并替换为新“恶意”用户的新版本。**  
#### 3. 虽然PyPI对于包库的作者有显示，方便我们进行判断，但是使用命令进行更新的时候，没有任何不一样的提示  
> PyPI 存储库具有一些防止模拟的保护措施，即能够区分包元数据中的作者姓名和发布包的实际用户。此措施有助于防止未经授权的用户错误地冒充合法作者的身份。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OlNJlSSibBiceqIUI0hicZ7Ianyq2iaurvGMB4HOXgQ1LMKRKTRZp7BtPob3YWiaW2PTBAicEJNX2VbXXjOhEB3OWXsQ/640?wx_fmt=other&from=appmsg "null")  
  
然而，这些保护措施似乎并没有减轻利用的情况。当我们运行以显示任何过时的包时，它将我们的冒名顶替包显示为原始包的最新版本 Latest （4.0.0） **名称相同，但代码却大不相同！**  
```
$ pip list --outdated
Package           Version Latest Type
----------------- ------- ------ -----
pip               23.0.1  24.0   wheel
revival-package   1.0.0   4.0.0  wheel
```  
  
pip install --upgrade:该命令也不会显示任何警告，**并将原始包替换为我们的 imposter 包**  
```
$ pip install --upgrade revival-package
Requirement already satisfied: revival-packagein./lib/python3.10/site-packages (1.0.0)
Collecting revival-package
Downloading revival-package-4.0.0-py3-none-any.whl (1.2 kB)
Installing collected packages: revival-package
Attempting uninstall: revival-package
Found existing installation: revival-package1.0.0
Uninstalling revival-package-1.0.0:
Successfully uninstalled revival-package-1.0.0
Successfully installed revival-package-4.0.0
```  
  
我们的实验表明，任何被移除的包都可以在被移除后立即被轻松劫持。不会显示任何警告，尽管 package 的作者已更改。  
## PyPI 的现有包劫持缓解措施  
  
PyPI 注册表包含防止使用方法注册欺骗性软件包的措施。在以下情况下，此方法  
将阻止注册新的 PyPI 包–[ProjectService.create_project](https://github.com/pypi/warehouse/blob/e8195e40986d63f9b72926a67eb6acfd43b36932/warehouse/packaging/services.py#L445)  
- • 如果规范化的包名称与现有的 PyPI 包名称匹配  
  
- • 如果规范化的包名称在 PyPI 的黑名单包列表中（PyPI 不会发布此列表）  
  
- • 如果规范化的包名称与任何现有的 PyPI 包名称相似。相似度使用以下  
代码计算：  
  
```
SELECT lower(
    regexp_replace(
        regexp_replace(
            regexp_replace($1,'(\.|_|-)','','ig'),
'(l|L|i|I)','1','ig'
),
'(o|O)','0','ig'
)
)
```  
```

```  
  
PyPI 的 SQL 查询，用于在注册新包时检测拼写错误  
  
此代码通过将外观相似的字符替换为相应的数字或删除句点、下划线和连字符等字符来防止简单的拼写错误。这种方法有助于防止注册名称与现有名称相似的软件包，从而降低具有欺骗性或误导性软件包名称的风险。  
  
这些措施涵盖了恶意软件开发人员使用的一些技术，但它们远非全面。虽然它们有助于防止创建某些恶意软件包，但它们并不能完全涵盖所有潜在的漏洞。例如，**如果被删除的项目名称被自动添加到包黑名单**中，现有的黑名单验证可以有效地防止 Revival Hijack 攻击。  
## 真实的攻击事件 -- pingdomv3投毒  
> **PyPI供应链攻击不仅仅是一种理论上的攻击，历史上已经有使用该方法进行恶意攻击的案例 --- pingdomv3投毒。**  
  
  
2024 年 4 月 12 日，“pingdomv3”包的异常活动。该软件包已经获得了新的所有者 。3 月 30 日，新所有者发布了一个看似良性的更新，紧随其后的是另一个版本，引入了可疑的 Base64 混淆有效载荷。  
```
import logging
try:
  from logging import NullHandler
  if NullHandler:
    import base64
    exec(base64.b64decode("dHJ5OgogIC....
...
```  
  
对 “pingdomv3” 程序包中的恶意代码进行加密  
1. 1.   
最初的包所有者   
**cheneyyan**  
 维护着一个   
GitHub 项目[3]  
，该项目现在不可用。他们发布了几个版本，但进行了细微的修改，最后一次合法更新是 2020 年 4 月 7 日的 0.0.6 版。  
  
1. 2.   
后续更新停止，直到 2024 年 3 月 27 日出现 0.1 版。此版本仅引入了一种从 setup.py 调用的方法，该方法显示以下消息：<font style="color:rgb(232, 62, 140);background-color:rgb(243, 243, 243);">'Hello, please avoid using this package as it is no longer supported. Contact cheney.yan@gmail.com!'</font>  
，这表明该项目已被放弃，并建议不要使用它。  
  
1. 3.   
3 月 30 日，即 0.1 版本发布几天后，原作者删除了该项目，因此项目名称可以注册。  
  
```
Summary: Pingdom v3 redeveloped
Home-page: https://github.com/jinnis423/pingdomv3
Author: Jinnis Author-email: jinnis.developer@gmail.com
```  
1. 1.   
几乎在该名称可用后，一个名为   
**Jinnis**  
 的帐户  
jinnis.developer@gmail.com[4]发布了一个同名的软件包，版本号较新 – 1.0.0。  
  
1. 2.   
几天后，即 2024 年 4 月 12 日，新开发人员发布了一个更新，其中包含我们团队及时检测到的恶意负载  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OlNJlSSibBiceqIUI0hicZ7Ianyq2iaurvGMJJfQUq2ib27GDAJoJAQ1kkMzpqRib1m8BwuonibJ5tF4XQSpwhoSC77Yg/640?wx_fmt=png&from=appmsg "null")  
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
  
  
  
  
