#  Google Cloud Build 漏洞可使黑客发动供应链攻击   
Sergiu Gatlan  代码卫士   2023-07-19 17:14  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRSylJK2k7H6mNqiaS2G6WRaeeK34cLHE6pe9VeOIHYiboAnKB0TMoayZCxFpHMLljzTnz9DnNuFiaqQ/640?wx_fmt=png "")  
  
  
  
专栏·供应链安全  
  
  
数字化时代，软件无处不在。软件如同社会中的“虚拟人”，已经成为支撑社会正常运转的最基本元素之一，软件的安全性问题也正在成为当今社会的根本性、基础性问题。  
  
  
随着软件产业的快速发展，软件供应链也越发复杂多元，复杂的软件供应链会引入一系列的安全问题，导致信息系统的整体安全防护难度越来越大。近年来，针对软件供应链的安全攻击事件一直呈快速增长态势，造成的危害也越来越严重。  
  
  
为此，我们推出“供应链安全”栏目。本栏目汇聚供应链安全资讯，分析供应链安全风险，提供缓解建议，为供应链安全保驾护航。  
  
  
注：以往发布的部分供应链安全相关内容，请见文末“推荐阅读”部分。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FIBZec7ucCiaWtRttKahE4rd7icPBW6mLiaWubZBfibktxAlCMH6dwLG1225lH4Xo8nmA5ENG7I4o905Qq23icpkHwg/640?wx_fmt=png "")  
  
  
  
**云安全公司 Orca Security 的研究人员从Google Cloud Build 服务中发现了一个严重的设计漏洞，可用于获得 Google Artifact Registry 代码仓库几乎完整的越权访问权限。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTu8oT9VKsUGXSqeT5FVBrjCXzSrvTtTJIzkxiaD1J3JRTiaekF7Cjic0GpZ2vViaD6LiasfhPCdDWfbow/640?wx_fmt=gif "")  
  
  
  
该漏洞被称为 “Bad.Build”，可使威胁行动者仿照 Google Cloud Build 管理持续集成和交付 (CI/CD) 服务的服务账户，针对部件注册表运行 API 调用并控制应用镜像。攻击者可注入恶意代码，在客户环境中部署恶意应用程序后，导致易受攻击的应用程序以及潜在的供应链攻击。   
  
研究员 Roi Nisimi 提到，“潜在影响可能多种多样，且适用于将 Artifact Registry 作为首要或次要的镜像仓库。首要的影响是破坏依赖于这些镜像的应用程序，导致拒绝服务、数据盗取以及向用户传播恶意软件的后果。和 SolarWinds以及最近的3CX和 MOVEit 供应链攻击一样，该事件会产生深远影响。” Rhino 安全实验室也发现并报告了该漏洞。不过他们利用该提权漏洞的方法更为复杂，涉及使用 GCP API 以及提取 Cloud Build Service Account 访问令牌。  
  
Orca Security 公司的方法是利用 cloudbuild.builds.create 许可提升权限并使攻击者通过 artifactregistry 许可篡改 Google Kubernetes Engine (GKE) docker 镜像，并以root 权限在 docker 容器中运行代码。  
  
Orca Security 公司的研究员报告该问题后，谷歌安全团队执行了部分修复方案，从与 Artifact Registry 无关的默认 Cloud Build Service Account 中调用 logging.privateLogEntries.list 许可。  
  
Nisimi 表示，“然而，谷歌的修复方案并未调用所发现的提权向量。它仅做了限制，将其转变为设计缺陷，但仍然导致组织机构易遭大型供应链风险。因此，组织机构密切关注Google Cloud Build 服务账户的默认行为十分重要。应用最小权限原则并执行云检测和响应能力来识别异常活动是降低风险的一些推荐措施。”  
  
建议 Google Cloud Build 客户将 Cloud Build Service Account 的默认权限修改为与需求匹配并删除对抗最小权限原则的权限凭据，缓解提权风险。  
  
4月份，谷歌还修复了一个 Google Cloud Platform (GCP) 安全漏洞 “GhostToken”，可使攻击者使用恶意 OAuth 应用在任意谷歌账户中安装后门。  
  
谷歌回应称，“我们专为发现和修复类似漏洞创建了漏洞奖励计划，感谢Oracle 和更广泛安全社区参与这些计划。感谢研究人员所做的工作，我们已经在6月初发布的安全公告中基于他们的报告集成了修复方案。”  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[速修复MOVEit Transfer 中的这个新0day！](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516712&idx=2&sn=a69d93a9d282a667bbbf33bc190b4dfb&chksm=ea94b342dde33a545caba266547e0a3d88b670ddfb23236984d8f468dfbefe639a55bb220239&scene=21#wechat_redirect)  
  
  
[MOVEit 文件传输软件0day被用于窃取数据](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516660&idx=1&sn=bb8f16701a800011a7e9bc8857cd59d2&chksm=ea94b09edde33988e2fee2cb9c23d0031149201a1722cfabc8899b76b31016a44a835836d8a9&scene=21#wechat_redirect)  
  
  
[MSI UEFI 签名密钥遭泄漏 恐引发“灾难性”供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516496&idx=2&sn=05ab156deeadfbc7ffedcd43bddc9323&chksm=ea94b03adde3392c30cec047021b94f806acaf2848ef08ac6345d0cbd3ef6ba3d31e4c124cc5&scene=21#wechat_redirect)  
  
  
[OilRig APT 组织或在中东地区发动更多 IT 供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516434&idx=1&sn=495e13a2f824e981c0123ff9cf6d7e39&chksm=ea94b078dde3396ef276b2ce6aadfb2039508719a61f133aacc6eeb736c54d51848992c51dad&scene=21#wechat_redirect)  
  
  
[“木马源”攻击影响多数编程语言的编译器，将在软件供应链攻击中发挥巨大作用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508877&idx=1&sn=8d51c2455cf523904c054a0396f94e87&chksm=ea9492e7dde31bf1510754ac2a12aba8deefa06d5ec5d94c759f12d8213d03fe438850192eba&scene=21#wechat_redirect)  
  
  
[GitHub 在 “tar” 和 npm CLI 中发现7个高危的代码执行漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507788&idx=2&sn=85eaec0dd13a76f5eda4cbf022bff87c&chksm=ea94ee26dde36730646cce927f8c597ec96be40b0e5200e5341f2340d7f76fedb4175dc270d5&scene=21#wechat_redirect)  
  
  
[流行的 NPM 包依赖关系中存在远程代码执行缺陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507695&idx=2&sn=1f32c3c66db05d617894efb36c680a30&chksm=ea94ef85dde366930a17a487f4d0d4cd298ad7e80a79fc2b298b3a5097cab26136d762023819&scene=21#wechat_redirect)  
  
  
[速修复！热门npm 库 netmask 被曝严重的软件供应链漏洞，已存在9年](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502778&idx=1&sn=5ad11d4289635b5d7f945c54cb2129f7&chksm=ea94fad0dde373c66f5c2024246f5c824cac549ac3dcfd85cc67fb238dabca34d7316fef9f65&scene=21#wechat_redirect)  
  
  
[Npm 恶意包试图窃取 Discord 敏感信息和浏览器文件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247494834&idx=2&sn=440c63e119a2e7827b83a08d4f665f4d&chksm=ea94ddd8dde354ce35f85b6022c626d9191ab27cd16f02308ee54c33783e00a7a9061986fb74&scene=21#wechat_redirect)  
  
  
[微软“照片”应用Raw 格式图像编码器漏洞 (CVE-2021-24091)的技术分析](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502693&idx=1&sn=0daf4033d561438e292f3eb4f09e5a9d&chksm=ea94fa0fdde37319e7b1a6767bf76396b3b91e1326ef9e397b38fe69443f651d7f52581ff9ec&scene=21#wechat_redirect)  
  
  
[速修复！热门npm 库 netmask 被曝严重的软件供应链漏洞，已存在9年](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502778&idx=1&sn=5ad11d4289635b5d7f945c54cb2129f7&chksm=ea94fad0dde373c66f5c2024246f5c824cac549ac3dcfd85cc67fb238dabca34d7316fef9f65&scene=21#wechat_redirect)  
  
  
[SolarWinds 供应链事件后，美国考虑实施软件安全评级和标准机制](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502539&idx=1&sn=a3452bb512355a45d323e75d24a5e38c&chksm=ea94fba1dde372b70045a76c19ed65df816838698c6a7f0eaefa5587dfa89684aedcd9c6d683&scene=21#wechat_redirect)  
  
  
[找到软件供应链的薄弱链条](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502483&idx=1&sn=afe45ab3ddd296de491255858d758821&chksm=ea94fbf9dde372ef7255f65c777b0f881f9268d4ce43a6f77e62cb356e67df09fdc4421eff09&scene=21#wechat_redirect)  
  
  
[GitHub谈软件供应链安全及其重要性](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502285&idx=1&sn=9815231c5e1c5e72f66258ae090020a1&chksm=ea94f8a7dde371b1ae04a6aaa9eb6cdba5a20abee2ec4f6729cab757d40d16bcf37d201eebd8&scene=21#wechat_redirect)  
  
  
[揭秘新的供应链攻击：一研究员靠它成功入侵微软、苹果等 35 家科技公司](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502189&idx=1&sn=14904e47dc36ba963579fa48bc36620c&chksm=ea94f807dde37111d8c72ddcfd27fa084917be4bcec5330cffa82c957c4c39a48634a9207039&scene=21#wechat_redirect)  
  
  
[开源软件漏洞安全风险分析](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247501564&idx=1&sn=4605ae4b98c423e354d7ec3af81eda5f&chksm=ea94f796dde37e80ea0e4d924c28b6abbf03fe882c4359757bc0082c7c2ac49f2bc3011a5847&scene=21#wechat_redirect)  
  
  
[开源OS FreeBSD 中 ftpd chroot 本地提权漏洞 (CVE-2020-7468) 的技术分析](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499356&idx=1&sn=f95ec3f9ca222c3ccef3d1162af259b8&chksm=ea94cf36dde34620d380b15d760f31aa5b3729cc379fa68a784ddcefde453df7db3a28a99f29&scene=21#wechat_redirect)  
  
  
[集结30+漏洞 exploit，Gitpaste-12 蠕虫影响 Linux 和开源组件等](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247499326&idx=2&sn=c4799bc67a235c3a5a9f278de525696a&chksm=ea94cf54dde3464296c96cebbf9c0ac1aeb0cf9b70bc2c2b740cb8dcd2333b4a0043d00dd109&scene=21#wechat_redirect)  
  
  
[限时赠书|《软件供应链安全—源代码缺陷实例剖析》新书上市](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507507&idx=1&sn=9bca6947933a205abe70545cc4bf0600&chksm=ea94ef59dde3664f1e08932c5bca27a5f687f5442b87349e4a024e5e5ffc49ac33fa62636d88&scene=21#wechat_redirect)  
  
  
[热门开源CI/CD解决方案 GoCD 中曝极严重漏洞，可被用于接管服务器并执行任意代码](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508832&idx=1&sn=bac2576345afca50ce02e42e2b32162b&chksm=ea94920adde31b1c9de180a18739a4121c8a470d0bf9c29051e309927a9fec05601b1e7d7596&scene=21#wechat_redirect)  
  
  
[GitKraken漏洞可用于盗取源代码，四大代码托管平台撤销SSH密钥](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508328&idx=2&sn=20845a55550656891327eb22afa578f1&chksm=ea949002dde3191422a2853c4f0d94a1724e27b877b15a947eb6dd04bafb5530778d5b1ec430&scene=21#wechat_redirect)  
  
  
[因服务器配置不当，热门直播平台 Twitch 的125GB 数据和源代码被泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508253&idx=1&sn=f294dd10f2b63f89cf06cea39073f247&chksm=ea949077dde319617f57b4a2ec5415ec8f5f6c9bbed8c22fd1d2f03cfc464b1cce59cd4bf11a&scene=21#wechat_redirect)  
  
  
[彪马PUMA源代码被盗，称客户数据不受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507826&idx=1&sn=2e6e2758899754d132df1e228cedac77&chksm=ea94ee18dde3670e95fb49cf3ee2427b4235c7c11ac2972a44d1c942991944e6832cdb28b4ba&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/google-cloud-build-bug-lets-hackers-launch-supply-chain-attacks/  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
