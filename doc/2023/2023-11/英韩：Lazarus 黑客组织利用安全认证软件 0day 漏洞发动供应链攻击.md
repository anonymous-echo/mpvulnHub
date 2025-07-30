#  英韩：Lazarus 黑客组织利用安全认证软件 0day 漏洞发动供应链攻击   
THN  代码卫士   2023-11-27 17:41  
  
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
  
  
  
**英国国家网络安全中心 (NCSC) 和韩国国家情报院 (NIS) 发布联合安全公告称，朝鲜国家黑客组织 Lazarus 利用 MagicLine4NX 软件中的一个 0day 对多家企业发动供应链攻击。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQUd826AhNT2zfjPpiadxGRicvhibIGAia7Z995691aIl8sKAxdfLeSF8icYWU1xH1zrZic2ia58Wa4Ub6MA/640?wx_fmt=png&from=appmsg "")  
  
  
MagicLine4NX 是由韩国公司 Dream Security 公司开发的一款安全认证软件，用于组织机构的安全登录操作。英韩两国在联合安全公告中提到，Lazarus 利用该产品中的一个 0day 漏洞攻击目标，而这些目标主要是韩国的机构，“2023年3月，网络行动者利用安全认证和联网系统中的软件漏洞获得对目标组织机构内网的越权访问权限。它利用 MagixLine4NX 安全认证程序中的一个软件漏洞，用于对目标联网计算机的初始入侵阶段，并利用该联网系统中的一个 0day 漏洞横向移动并获得对信息的越权访问权限。”  
  
攻击以攻陷一家媒体机构网站开始，在该网站中的一篇文章中嵌入恶意脚本，执行水坑攻击。当某些IP地址范围的特定目标访问该受陷网站上的这篇文章时，恶意脚本就会执行恶意代码，触发 MagicLine4NX 软件中的漏洞，影响1.0.0.26之前的版本。这导致受害者计算机连接到攻击者的C2服务器，通过利用联网系统中漏洞的方式访问互联网端服务器。Lazarus 组织被指利用该系统的数据同步功能项业务端服务器传播信息窃取代码，从而攻陷目标组织机构中的个人电脑。被释放的代码与两台C2服务器连接，一台服务器作为中间网关，另一台位于互联网。该恶意代码的功能包括侦查、数据提取、下载和执行来自C2的加密payload以及横向网络移动。  
  
这起供应链攻击被命名为 “Dream Magic”。  
  
  
**Lazarus 供应链攻击活动**  
  
  
  
  
Lazarus 黑客组织被指与朝鲜政府有关，被指一直将供应链攻击和 0day 漏洞利用作为网络战术的一部分。  
  
2023年3月，Lazarus 子组织 “Labyrinth Chollima”被指针对 VoIP 软件厂商3CX 发布供应链攻击，攻陷全球多家高级别公司。[上周五，微软披露了一起针对 CyberLink 的供应链攻击，指出Lazarus 组织利用该攻击木马化数字签名的 CyberLink 安装程序，至少通过 “LambLoad” 恶意软件感染了一百台计算机](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518210&idx=1&sn=3c6b327672ccb8c0b44cae5a8fc02e20&chksm=ea94b968dde3307e207d33f8f67304380f153cc3002f0d518d15331016a32e277493084c86fe&scene=21#wechat_redirect)  
。  
  
Lazarus 黑客组织被指通过这些攻击类型攻陷特定企业，或者进行网络间谍活动、或者进行金融欺诈或盗取密币。今年早些时候，网络安全公告提醒称，Lazarus 组织通过偷盗资金来支持朝鲜行动。CISA 在安全公告中提到，“当局机构评估认为，源自这些密币行动中的数量不明的收入支撑国家级别的优先事务和目标，包括对美国和韩国政府发动网络行动，具体目标包括美国国防信息网络和国防工业基地成员网络。”  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[Okta 支持系统遭攻陷，已有Cloudflare、1Password等三家客户受影响](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517967&idx=1&sn=a0c2ff2dfd52aa69d170f3e95247f143&chksm=ea94b665dde33f73c593e4082e0b1ee4e39fca8e1f3c753c75baf229f798e18e28af2788be4b&scene=21#wechat_redirect)  
  
  
[黑客攻陷Okta发动供应链攻击，影响130多家组织机构](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513692&idx=2&sn=9edbf81f8e756e90d33627cdfe3796f3&chksm=ea948736dde30e20a3b8750b3189dd23d0baf268f08e98448ec6421a9d7649d3cfc08f11f960&scene=21#wechat_redirect)  
  
  
[Okta 结束Lapsus$ 供应链事件调查，称将加强第三方管控](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511475&idx=1&sn=1ea2d1ecbccc18f96cf4a2042cea226d&chksm=ea949cd9dde315cf066c77d11309916d7926f24db191be889382dbb7926399c047ad7487ee78&scene=21#wechat_redirect)  
  
  
[Okta 提醒：社工攻击正在瞄准超级管理员权限](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517538&idx=2&sn=8b83afe723575b7a69c7ea7a0c21dbd2&chksm=ea94b408dde33d1e969877340c12536b88f0e6874c0bf635c1489627d5749af02612fca74ee6&scene=21#wechat_redirect)  
  
  
[《软件供应商手册：SBOM的生成和提供》解读](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511570&idx=1&sn=a8eda02cab19a290202dd91895bd3887&chksm=ea949f78dde3166e104a4d6a2c2c9e1b32d673f6589993a2f2bfb94740bdc6cdc0088dc8c273&scene=21#wechat_redirect)  
  
  
[Telegram 和 AWS等电商平台用户遭供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517920&idx=2&sn=9b81bba53ca92b9dba48012df9a9d2cb&chksm=ea94b78adde33e9c5b9a7a2184d0c433e97efba3d73c58471d585199cd6d4d88409f7bd57770&scene=21#wechat_redirect)  
  
  
[美国商务部发布软件物料清单 (SBOM) 的最小元素（上）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509892&idx=1&sn=f149d024a5a8742859d3b08d90a9111e&chksm=ea9496eedde31ff8e60949842119828151d8a0200b56b5f524e2851e9a5913ba90b605ad7fed&scene=21#wechat_redirect)  
  
  
[美国商务部发布软件物料清单 (SBOM) 的最小元素（中）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509894&idx=1&sn=b4815181d043ae4843fd1d3cea5e196b&chksm=ea9496ecdde31ffa29e43cbaf6c60811908b0eb21e9fd1e23d7c161ae675cb83b35359bcfb08&scene=21#wechat_redirect)  
  
  
[美国商务部发布软件物料清单 (SBOM) 的最小元素（下）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509930&idx=1&sn=3573aa307f009e3709fcbb2ac5498e66&chksm=ea9496c0dde31fd6d2f330cd5526fe409c08648ef2236d4674ae043a9939d95df908121c8f93&scene=21#wechat_redirect)  
  
  
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
  
  
[多租户AWS漏洞暴露账户资源](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514718&idx=1&sn=171e74c0abec3a1060332412667c59e2&chksm=ea948b34dde302221841c5c6fc01ccda3bf10122f733119c7dc0a8393f19753e6b8a66979946&scene=21#wechat_redirect)  
  
  
[适用于Kubernetes 的AWS IAM 验证器中存在漏洞，导致提权等攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512889&idx=4&sn=bd3623a8d3f38a4206124b8681f1c510&chksm=ea948253dde30b457da57e1cfc42ab6fc1b7c06335250b93b2f6b89654f0b83884057e98fbd5&scene=21#wechat_redirect)  
  
  
[PyPI 仓库中的恶意Python包将被盗AWS密钥发送至不安全的站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512575&idx=2&sn=5af81a53d9263bf10273d86868a77287&chksm=ea948095dde309830949a85914d18a896ce49535f37a9c0cf802e2d84d4dbf264c0e5795396b&scene=21#wechat_redirect)  
  
  
[热门PyPI 包 “ctx” 和 PHP库 “phpass” 长时间未更新遭劫持，用于窃取AWS密钥](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511966&idx=1&sn=77856cc7ec3f5318efb4f18f2a8ddf66&chksm=ea949ef4dde317e2a06b85bfc4ca7d162951708a197fc45a2b94119ddf30e4457c29386705b2&scene=21#wechat_redirect)  
  
  
[如何找到 AWS 环境下应用程序中易于得手的漏洞？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509668&idx=1&sn=f66860a4ec28d1117be19a6dcafba1e4&chksm=ea9497cedde31ed8da20a2e8d3b496a000f09f5ef0d93a065eae9c2f68681a78b37571735a7c&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/uk-and-south-korea-hackers-use-zero-day-in-supply-chain-attack/  
  
  
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
  
