#  GitLab爆出安全漏洞，允许黑客接管账户   
小王斯基  FreeBuf   2024-05-25 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibEhaJRItpTlghAd8LH0u4WVK7wtCsn73eZssREAy0Qk2PfAIFIxVhHm2mC8AxcxdltJPyCvE8zeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibEhaJRItpTlghAd8LH0u4Wc3ScR2GiaURqc9n8ME41NobLiaJtlo1jicZhVWrW85nqg3OibHp7yqlqJw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JVmdRfia5L2Vic710iciaxKib35h0aRskIApahCm61u7wEY3kdmLfAicPXYhKC5matds5LHWSxooU6yduz/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JVmdRfia5L2Vic710iciaxKib35h0aRskIApahCm61u7wEY3kdmLfAicPXYhKC5matds5LHWSxooU6yduz/640?wx_fmt=svg&from=appmsg "")  
  
  
  
  
近日，GitLab 又爆出一个安全漏洞（被追踪为 CVE-2024-4835），未经认证的威胁攻击者能够利用该漏洞在跨站脚本 (XSS) 攻击中，轻松接管受害者账户。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibEhaJRItpTlghAd8LH0u4WnicCnogU8gAru7kPlNKDtcuO1u57v97SMwzHbxhVWD38tiaZIyIVSXLw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
GitLab ：一个基于网络的 Git 存储库，主要面向需要远程管理代码的开发团队，目前共拥有约 3000 万注册用户和 100 万付费客户。  
  
  
收到 CVE-2024-4835 安全漏洞通知后，GitLab 方面表示，在近期发布的 GitLab 社区版（CE）和企业版（EE）的17.0.1、16.11.3 和 16.10.6 版本中都修复了安全漏洞问题，强烈建议所有 GitLab 用户立即升级到其中一个版本。  
  
> CVE-2024-4835 安全漏洞是 VS 代码编辑器（Web IDE）中的一个 XSS 缺陷，允许威胁攻击者利用恶意制作的页面窃取部分信息。值得一提的是，虽然威胁攻击者可在未经身份验证的攻击中利用该漏洞，但仍需要与用户交互，这就增加攻击的复杂性。  
  
  
  
GitLab 公司还修复了其他六个中等严重程度的安全漏洞。其中，主要包括通过 Kubernetes 代理服务器的跨站请求伪造（CSRF）漏洞 CVE-2023-7045 和一个可让威胁攻击者破坏 GitLab 网络资源加载的拒绝服务漏洞 CVE-2024-2874。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibEhaJRItpTlghAd8LH0u4W32UGXxqCI3KCaT87xPCeKvYvwVoTajP03n23rsXs37XM7H4W4TGu2w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**GitLab 安全漏洞频出**  
  
  
  
众所周知，GitLab 存放着包括 API 密钥、专有代码等各种类型的敏感数据，因此早就成为了很多威胁攻击组织眼中的「香饽饽」。一旦有威胁攻击者成功在 CI/CD（持续集成/持续部署）环境中插入恶意代码，破坏组织的资源库，那么被劫持的 GitLab 账户就会面临着重大的网络安全风险，甚至引发严重供应链攻击。  
  
  
早些时候，CISA 曾经发出警告，威胁攻击者目前正积极利用 GitLab 在 1 月份修补零点击账户劫持漏洞 CVE-2023-7028，漏洞允许未经认证的威胁攻击者通过密码重置接管 GitLab 账户。当时，Shadowserver 发现超过 5300 个在线暴露的 GitLab 漏洞实例（截止到目前仍旧有 2084  个的实例可以访问）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibEhaJRItpTlghAd8LH0u4WoIgumMrSV61nJeu9VowicBUrQdSiaoKGXZMicOZeVy4icPkUpAJ5SiavdgA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
2023 年 5月，GitLab 突然发布了 16.0.1 版紧急安全更新，解决了一个被追踪为 CVE-2023-2825 的严重性路径遍历漏洞，该漏洞 CVSS 评分10.0。  
  
  
据悉，CVE-2023-2825 漏洞源于路径遍历问题，当一个附件存在于至少五个组内嵌套的公共项目中时，未经认证的威胁攻击者便可以在服务器上读取任意文件。不仅如此，一旦成功利用 CVE-2023-2825 漏洞，还可能会非法访问包括专有软件代码、用户凭证、令牌、文件和其他私人信息在内的敏感数据。  
  
  
好消息是，CVE-2023-2825 漏洞问题与 GitLab 如何管理或解决嵌套在几级组层次结构中的附件文件的路径有关，因此安全漏洞只能在特定条件下才会触发，即当公共项目中有一个附件嵌套在至少五个组中时，好在这并不是所有 GitHub 项目遵循的结构。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/high-severity-gitlab-flaw-lets-attackers-take-over-accounts/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493767&idx=1&sn=9b3400e4901e706ab29b1df75b4906fa&chksm=ce1f1218f9689b0e58e78c64d26531983b65daede2e93dbecd43d4b134cae1212d4fa69cf29b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493743&idx=1&sn=2a3f519da5fa72beb3c1146867476b51&chksm=ce1f12f0f9689be6613e69886c8f6fbfbb131c79c0b2b2e1a7885c485fec8f305c9beaa4927a&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
