> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651325085&idx=3&sn=3fdc985551c6f7ef9efd22161d1894bc

#  Windows Server 2025黄金dMSA漏洞使攻击者永久获取访问权限  
 FreeBuf   2025-07-17 10:32  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR381j7bBhb9jB2ODTEZ7HekWLic3vgG17zYbIZKBnXhWC3cLPv0fgNTicibTvHGbicPSogtiaZJ9VoIU2AA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
网络安全研究人员近日披露了Windows Server 2025中委托管理服务账户（dMSA，Delegated Managed Service Accounts）存在的"关键设计缺陷"。据Semperis公司向The Hacker News提供的报告显示："该漏洞可能导致高危害攻击，使攻击者能够实施跨域横向移动，并永久获取Active Directory中所有托管服务账户及其资源的访问权限。"  
  
  
**Part01**  
## 漏洞技术原理  
##   
  
该漏洞被命名为**黄金dMSA（Golden dMSA）**  
，攻击者成功利用后，可绕过身份验证机制，为所有委托管理服务账户（dMSA）和组管理服务账户（gMSA，group Managed Service Accounts）及其关联服务账户生成密码。网络安全公司评估其攻击复杂度较低，因为该漏洞显著简化了暴力破解密码生成的难度。  
  
  
但攻击者需事先获取密钥分发服务（KDS，Key Distribution Service）根密钥，这类密钥通常仅限特权账户（如域管理员、企业管理员和SYSTEM账户）持有。KDS根密钥被视为微软gMSA基础设施的核心组件，作为主密钥使攻击者无需连接域控制器即可推导出任何dMSA或gMSA账户的当前密码。  
  
  
安全研究员Adi Malyanker指出："该攻击利用了一个关键设计缺陷：密码生成计算使用的结构包含可预测的时间相关组件，仅有1024种可能组合，使得暴力破解在计算上变得轻而易举。"  
  
  
**Part02**  
## 攻击影响范围  
  
  
委托管理服务账户是微软为替代传统服务账户而设计的新功能，随Windows Server 2025推出，旨在防范Kerberoasting攻击。该功能将身份验证直接绑定到Active Directory（AD）中明确授权的机器，从而消除凭据窃取风险。只有AD中映射的特定机器身份才能访问账户。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR381j7bBhb9jB2ODTEZ7HekWQH8Mu4lf2xF7Enagxr3XzVhZFSsxyYSwuYChfxtCtibe4F2EuwGicSXw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
黄金dMSA攻击与黄金gMSA攻击类似，攻击者在域内获取提升权限后，可通过四个步骤实施攻击：  
- 通过在域控制器上提升至SYSTEM权限提取KDS根密钥材料  
  
- 使用LsaOpenPolicy和LsaLookupSids API或基于轻量目录访问协议（LDAP）的方法枚举dMSA账户  
  
- 通过定向猜测识别ManagedPasswordID属性和密码哈希  
  
- 为与泄露密钥关联的任何gMSA或dMSA生成有效密码（即Kerberos票据），并通过哈希传递（Pass the Hash）或超哈希传递（Overpass the Hash）技术进行测试  
  
Malyanker强调："获取KDS根密钥后，此过程无需额外特权访问，使其成为特别危险的持久化方法。该攻击凸显了托管服务账户的关键信任边界问题——它们依赖域级加密密钥保障安全。虽然自动密码轮换能有效防御常规凭据攻击，但域管理员、DNS管理员和打印操作员可完全绕过这些保护，危及整个林中的所有dMSA和gMSA。"  
  
  
**Part03**  
## 企业级安全威胁  
  
  
Semperis指出，黄金dMSA技术会将入侵转化为林范围的持久后门，因为从林中任意域获取KDS根密钥就足以攻破该林中所有域的每个dMSA账户。这意味着单次KDS根密钥提取就可被武器化，实现跨域账户入侵、全林凭据收集以及利用被攻陷dMSA账户进行跨域横向移动。  
  
  
Malyanker特别指出："即使在配置多个KDS根密钥的环境中，系统出于兼容性考虑始终使用第一个（最旧的）KDS根密钥。这意味着我们入侵的原始密钥可能因微软的设计而长期保留——形成可持续数年的持久后门。"  
  
  
更令人担忧的是，该攻击完全绕过了常规的凭据保护（Credential Guard）机制——这些机制本应用于保护NTLM密码哈希、Kerberos票据授予票据（TGT）和凭据，确保只有特权系统软件能访问它们。  
  
  
微软在2025年5月27日收到负责任的漏洞披露后回应："如果攻击者拥有用于派生密钥的机密信息，就能以该用户身份进行验证。这些功能从未设计用于防范域控制器被入侵的情况。"Semperis已发布开源概念验证（PoC）代码演示该攻击。  
  
  
Malyanker警告："从入侵单个域控制器开始，最终将演变为控制整个企业林中所有受dMSA保护的服务。这不仅是权限提升，更是通过单个加密漏洞实现企业级的数字统治。"  
  
  
**参考来源：**  
  
Critical Golden dMSA Attack in Windows Server 2025 Enables Cross-Domain Attacks and Persistent Access  
  
https://thehackernews.com/2025/07/critical-golden-dmsa-attack-in-windows.html  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324992&idx=1&sn=8303e67651ddba23a73497aeb18955fa&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
