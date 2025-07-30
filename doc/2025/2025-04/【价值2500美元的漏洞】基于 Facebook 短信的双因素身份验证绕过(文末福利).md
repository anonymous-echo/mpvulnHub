#  【价值2500美元的漏洞】基于 Facebook 短信的双因素身份验证绕过(文末福利)   
Moaz Adel  安全视安   2025-04-03 18:53  
  
**声明**  
**：该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。**  
  
原文链接：  
https://moaz219.blogspot.com/2024/08/facebook-sms-based-two-factor.html  
  
漏洞允许攻击者禁用受害者 Facebook 帐户的基于短信的双重身份验证。  
## 了解漏洞的先决条件  
  
要了解此漏洞，首先需要了解几个关键概念。  
### 1. 账户中心：  
  
Meta 提供的帐户中心为用户提供了一个统一的界面，用于管理和整合他们在 Facebook、Instagram 和其他 Meta 服务上的体验。它集中了设置、权限和帐户数据管理，简化了 Meta 旗下多个关联帐户的处理。有关帐户中心的更多信息，您可以访问  
此页面  
。  
### 2.基于 Facebook 短信的双因素身份验证：  
  
在 Facebook 上，如果您的帐户链接到一个电话号码，并且您使用该电话号码启用了基于短信的双因素身份验证 (2FA)，而当该号码链接到另一个 Facebook 帐户时，它将自动从您的帐户中删除，从而禁用基于短信的 2FA。  
## 利用漏洞  
  
在测试帐户中心时，我发现如果您在帐户中心有两个关联的帐户，并且其中一个帐户关联了一个电话号码，则可以将此号码转移到另一个帐户。例如，如果您已关联 Facebook 和 Instagram 帐户，并且您的 Facebook 帐户关联了一个电话号码，则可以从 Instagram 打开帐户中心，并将此号码从您的 Facebook 帐户添加到您的 Instagram 帐户，反之亦然。  
  
这让我想到了一个场景：假设受害者有两个关联的 Instagram 和 Facebook 帐户，并且有一个电话号码与他们的 Facebook 帐户相关联。如果受害者使用此电话号码在其 Facebook 帐户上启用了 2FA，并且攻击者获得了受害者 Instagram 帐户的访问权限，攻击者可以将电话号码从受害者的 Facebook 帐户（他们无权访问）转移到 Instagram 帐户（他们确实可以访问）。然后，通过将受害者的 Instagram 帐户链接到他们控制的 Facebook 帐户，攻击者可以从受害者的 Facebook 帐户中删除电话号码，从而有效地禁用 2FA。  
  
我尝试通过访问受害者的 Instagram 帐户并尝试将受害者的电话号码从他们的 Facebook 帐户转移到 Instagram 帐户。不幸的是，这次尝试失败了，因为我被提示重新验证电话号码，所以我无法完成转移。  
  
经过进一步考虑，我想到了一个不同的想法：如果我将我的 Meta 帐户添加到受害者的帐户中心，然后尝试将受害者的电话号码从 Meta 帐户中心转移到 Instagram 帐户，会怎么样？以下是我所做的：  
  
我将我的 Meta 帐户添加到受害者的帐户中心。然后，从 Meta 帐户中心，我成功地将受害者的电话号码转移到 Instagram 帐户。我迅速将 Instagram 帐户连接到我拥有的 Facebook 帐户，并将电话号码从 Instagram 帐户转移到我的 Facebook 帐户。此操作从受害者的 Facebook 帐户中删除了电话号码，从而禁用了他们的 2FA。  
## 重现步骤  
### 受害者方面：  
1. 受害者有两个关联的 Instagram 和 Facebook 帐户。  
  
1. 受害者有一个与其 Facebook 账户关联的电话号码。  
  
1. 受害者使用该电话号码在其 Facebook 帐户上启用了 2FA 短信。  
  
### 从攻击者的角度来说：  
1. 攻击者获得了受害者 Facebook 和 Instagram 帐户的凭证。  
  
1. 攻击者的目标是绕过 Facebook 2FA 并获取受害者 Facebook 帐户的访问权限。  
  
1. 攻击者登录受害者的 Instagram 帐户。  
  
1. 攻击者导航到  
https://accountscenter.meta.com/accounts  
并将受害者的 Instagram 帐户添加到他们的 Meta 帐户。  
  
1. 攻击者导航到  
https://accountscenter.meta.com/personal_info/contact_points  
并将受害者的电话号码从受害者的 Facebook 帐户添加到受害者的 Instagram 帐户。  
  
1. 攻击者导航到  
https://accountscenter.instagram.com/accounts/  
，删除受害者的 Facebook 帐户，并添加他们自己的帐户。  
  
1. 攻击者导航到  
https://accountscenter.instagram.com/personal_info/contact_points/  
并将电话号码添加到新添加的 Facebook 帐户。  
  
### 受害者方面：  
1. 受害者导航到  
https://accountscenter.facebook.com/password_and_security/two_factor  
并发现他们的 Facebook 2FA 已被禁用。  
  
## 概念验证视频  
  
详细演示请参考下面的PoC视频：  
  
## 影响  
  
该漏洞允许攻击者绕过受害者 Facebook 帐户的 2FA，从而可能导致未经授权访问和控制受害者的 Facebook 帐户。  
# 免费网络安全资料PDF大合集  
  
**链接：https://pan.quark.cn/s/41b02efa09e6**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/Pf9NC3AaQF5xOsytm8HnicSzbLxpd8ftiayzOUDHO0ThH4c5u1nj0xL95BmAMgOfsc1d426a81FwEcpMYiazDBNRQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
