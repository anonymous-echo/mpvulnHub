#  GitHub 曝出漏洞，或导致 4000 多个存储库遭受劫持攻击   
 网络安全应急技术国家工程中心   2023-09-14 15:38  
  
The Hacker News 网站披露，安全研究员发现 GitHub 中存在一个新安全漏洞，该漏洞可能导致数千个存储库面临劫持攻击的风险。据悉，在 2023 年 3 月 1 日漏洞披露后，微软旗下的代码托管平台已于 2023 年 9 月 1 日解决了安全漏洞问题。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38KtN68B08ibG5xQ73MZ8XDwDKMoq3MpuZd54yfh4u4fRAdnCFNTbzYNXX2rlYc3dA8Xv3SYuewuVA/640?wx_fmt=jpeg&wxfrom=13&tp=wxpic "")  
  
Checkmarx 安全研究员 Elad Rapoport 在与 The Hacker News 分享的一份技术报告中指出，漏洞问题影响深远，一旦网络攻击者成功利用安全漏洞，便可以劫持使用 Go、PHP 和 Swift 等语言的 4000 多个代码包以及 GitHub 操作，从而影响开源社区的安全。  
  
repocapping 是存储库劫持（repository hijacking）的简称，是一种威胁攻击者能够绕过一种流行的存储库命名空间退役的安全机制并最终控制存储库的技术。（该保护措施的作用是防止其他用户在重命名其用户帐户时创建与包含 100 个以上克隆的存储库同名的存储库。）换句话说，用户名和存储库名称的组合被视为“已退役”状态。  
  
如果这一保障措施被轻易规避，威胁攻击者就可以用相同的用户名创建新账户并上传恶意存储库，从而可能导致软件供应链攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38KtN68B08ibG5xQ73MZ8XDw3ics8VqsQNU8ecaSetWQYmia4SkBs3wDARX30pPlk9VESGrkGp4d5JJw/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Checkmarx 提出的新方法主要利用了创建存储库和重命名用户名之间的潜在竞争条件来实现劫持存储库。具体来说，需要以下步骤：  
> 受害者拥有命名空间 "victim_user/repo  
> 受害者将 "victim_user "重命名为 "renamed_user"  
> 受害者用户/repo "版本库已退役  
> 用户名为 "acker_user "的威胁攻击者同时创建一个名为 "repo "的存储库，并将用户名 "acker_user "重命名为 "victor_user"  
> 最后一步是使用 API 请求创建版本库，并截获重命名请求以更改用户名。  
  
  
值得一提的是，GitHub 在近九个月前还修补了一个类似的绕过漏洞，该漏洞可能会为劫持攻击打开“方便之门”。  
  
**参考资料：**  
  
https://thehackernews.com/2023/09/critical-github-vulnerability-exposes.html  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
