#  助攻黑客的严重漏洞？不符合GOOGLE的威胁模型，不予解决！   
 网络安全应急技术国家工程中心   2023-11-16 15:17  
  
Bitdefender研究人员11月15日撰文，揭露了Google Workspace中的新漏洞，这个漏洞可能导致勒索软件攻击、数据泄露和口令解密。研究人员表示，这些方法还可以用于通过自定义权限访问谷歌云平台（GCP），并且可以在机器之间横向移动。然而，Bitdefender负责任地向谷歌披露了这些发现之后，谷歌确认没有计划解决这些发现，因为这超出了他们的特定威胁模型。需要注意的是，这不是责备的问题，而是责任的问题。尽管谷歌基于他们的风险评估和安全优先级做出了深思熟虑的选择。但仅仅因为某些漏洞超出了威胁模型的范围，就置之不理，并不意味着威胁行为者不会利用它们。依赖于受感染本地计算机的漏洞（例如Bitdefender强调的漏洞）不被视为谷歌特有的漏洞，因为通过恶意软件等方法进行的攻击应该由组织的现有安全控制来应对。在漏洞披露过程中谷歌告诉研究人员，数据存储行为符合Chrome的预期做法。Bitdefender强调不应掉以轻心，其研究中强调的漏洞实际上是完全可利用的。实际上，这种漏洞/缺陷对于攻击者加固据点，横向扩大战果，非常有价值。  
  
针对使用Windows的组织  
  
这些攻击取决于组织对Windows版Google Credential Provider(GCPW)的使用，该提供程序提供移动设备管理(MDM)和单点登录 (SSO)功能。  
  
当计算机上安装GCPW时，会创建一个本地Google帐户和ID管理(GAIA)帐户，该帐户具有提升的权限。然后，GCPW将凭据提供程序添加到Windows的本地安全机构子系统服务(LSASS)，以便用户可以使用其工作区凭据登录Windows计算机。  
  
GAIA为使用GCPW进行身份验证的新用户创建一个新的本地帐户，将该本地帐户与工作区帐户相关联。本地帐户中还存储了一个刷新令牌，用于维护对Google API的访问，从而无需不断重新进行身份验证。  
  
生成访问令牌并绕过MFA  
  
尽管在绕过MFA之前需要进行本地妥协（compromise），但考虑到稍后可以将其链接起来窃取明文口令，因此该漏洞还是值得注意的。  
  
攻击者可以根据令牌的寿命在两个不同的区域窃取帐户的刷新令牌。创建后，它们首先会短暂存储在Windows注册表值中，并使用CryptProtectData函数进行加密。然后，它们会更永久地存储在用户的Chrome配置文件中。  
  
在这两个位置都可以解密。在Windows注册表中，可以使用经常被滥用的工具（例如Mimikatz）或通过调用CryptUnprotectData函数来解密刷新令牌。Bitdefender表示，这是一种更隐蔽的方法，但只能在注册表中保留较短的时间。  
  
存储在Chrome配置文件中后进行解密则相反。它在那里停留的时间更长，可以更确定其位置，但噪音更大，增加了被发现的机会。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icX4CWLL4tAmb3V5SEaq787qyu1go6UZ8lCTkXOkzicW2PdN5ic1m6fPnlfLH2hZ6U2CQxmicNaicvcCwA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Bitdefender说明了访问令牌是如何被盗的  
  
然后可以通过特制的POST请求向攻击者颁发令牌，授予攻击者访问令牌范围内任何服务的权限。Gmail和Google Drive等服务中的数据泄露以及大量其他滥用行为是可能的。  
  
Bitdefender表示，Vault API是一项“有趣”的滥用服务，它能够窃取组织内所有用户的所有电子邮件和文件。  
  
如果由于某种原因攻击者无法提取令牌，他们可以通过将令牌句柄的值更改为无效或空值来强制重新进行身份验证。  
  
恢复明文口令  
  
Bitdefender表示，身份验证绕过漏洞可用于帮助攻击者检索解密用户口令所需的RSA密钥，这是研究中“更严重”的漏洞。  
  
报告称：“访问令牌一旦被盗，就会导致攻击者在令牌权限定义的范围内获得有限的访问权限，从而带来安全风险。”“这些代币通常是有时间限制的，并且有特定的范围限制。  
  
“相比之下，访问明文凭据（例如用户名和口令）代表了更严重的威胁。这是因为它使攻击者能够直接冒充合法用户并不受限制地访问其帐户，从而可能导致帐户完全接管。”  
  
攻击者可以利用之前的漏洞来生成具有OAuth范围的新访问令牌，然后向特定的未记录的API端点发送GET请求以检索所需的RSA密钥。  
  
横向运动  
  
横向移动漏洞主要适用于虚拟机(VM)部署，并使用克隆VM的常见做法。  
  
在新计算机上安装GCPW时创建的GAIA帐户始终会生成唯一的口令，但如果该计算机是通过克隆另一台计算机创建的，则所有计算机上的口令将相同。  
  
在从另一台计算机克隆多台计算机的情况下，如果攻击者仅获取其中一台计算机的凭据，则攻击者可以遍历这些计算机。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176nFsh4QCPWDf5OzHMfwWM2lL6qNdTgqFk6Vtn8Df04dWzzHuuvMTyquicyLSiaxeUibKdRCOLn6lo94A/640?wx_fmt=jpeg "")  
  
克隆机器如何促进横向移动  
  
Bitdefender技术解决方案总监Martin Zugec表示：“虚拟机克隆非常常见，尤其是在VDI或RDP部署等特定场景中。”  
  
“任何促进单一映像管理的解决方案都容易受到这种攻击方法的影响。该漏洞目前尤其重要，像LockBit这样的威胁参与者会积极利用CitrixBleed通过远程桌面解决方案获得对网络的未经授权的访问。  
  
“单一映像管理的吸引力是VDI和RDP部署中的一个关键功能。它使您能够高效部署数万台计算机，同时仅处理最少量的虚拟机映像。”  
  
该设备最初的妥协在这里发挥了作用，Bitdefender表示，找到GAIA帐户凭据的方法是使用能够列出LSASS中存储的秘密的恶意软件，例如Mimikatz。  
  
谷歌强调没有  
问题  
  
Bitdefender概述的漏洞利用有一些警告，主要的一点是执行其中任何一个漏洞都需要对本地计算机进行突破控制（comprimise）。这是谷歌拒绝解决这些问题的主要原因，因为需要本地妥协的攻击不在其威胁模型之内。  
  
当本地计算机受到损害达到Mimikatz等恶意软件可以运行的程度时，Bitdefender定义的漏洞仅提供给攻击者的可能性的一小部分样本。  
  
在最初的漏洞披露过程中，Bitdefender安全研究员Radu Tudorică认为，由于本地泄露可能导致对组织的云基础设施的攻击，因此值得关注。  
  
Chromium项目的Roger Tawa回应说：“即使没有GCPW，刷新令牌也会存储在Chrome配置文件内的磁盘上，并使用与存储在注册表中相同的机制进行加密。  
  
“以同一操作系统用户身份运行应用程序始终可以提取该值。使用GCPW，该值会在复制到磁盘上的配置文件之前暂时存储在注册表中。Chrome安全部门当时对此进行了审核，并认为与任何其他值一样安全。Chrome用户数据的其他部分并遵循Windows的最佳实践。”  
  
对于强制重新认证盗取代币的问题，他还表示，这并不会增加代币被盗的风险。  
  
“如果应用程序可以写入HKLM来强制重新身份验证，它也可以直接从磁盘上的配置文件中读取加密的刷新令牌。”  
  
该漏洞报告促使Chrome安全团队进行了审查，并审议了近一个月，但最终给出了“无法修复”的结论。  
  
Bitdefender建议，已发现的针对Google Workspace的攻击方法会带来安全风险，但需要注意的是，这些攻击方法首先需要入侵本地设备。防御建议包括，检测和响应：应优先考虑加强组织的检测和响应能力。投资先进的威胁检测解决方案，例如GravityZone XDR或Bitdefender MDR，以快速识别和响应异常或未经授权的访问尝试。事件响应计划：制定并维护事件响应计划，以有效解决本地设备受损问题。该计划应概述安全事件的调查、缓解和恢复程序。  
  
**参考来源：**  
  
1.https://www.theregister.com/2023/11/15/google_workspace_weaknesses_allow_plaintext/  
  
2.https://www.bitdefender.com/blog/businessinsights/the-chain-reaction-new-methods-for-extending-local-breaches-in-google-workspace/  
  
  
  
原文来源：网空闲话plus  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
