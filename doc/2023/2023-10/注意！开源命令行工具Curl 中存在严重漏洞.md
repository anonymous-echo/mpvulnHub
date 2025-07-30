#  注意！开源命令行工具Curl 中存在严重漏洞   
JONATHAN GREIG  代码卫士   2023-10-09 18:04  
  
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
  
  
****  
**基础性开源命令行工具 curl 的维护人员提醒称，本周将修复两个漏洞，其中一个是高危漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQlib8xW4DWtdQNeLNx139icWx4JWRSGlic9PvFibVtdII0pvHdl8JypIuITnQ80XAAdMZrjnwJrtBxUQ/640?wx_fmt=gif "")  
  
  
Curl 为很多网络协议如SSL、TLS、HTTP、FTP、SMTP 等提供支持，供广大开发人员和系统管理员“与API交互、下载文件并在多种基于互联网的任务中创建自动化工作流。“  
  
上周三，Curl 工具的维护人员在 GitHub 安全公告中提到，将为一个高危漏洞CVE-2023-38545和一个低危漏洞CVE-2023-38546发布修复方案。curl 更新将在10月11日发布以修复这些漏洞。CVE-2023-38545同时影响 curl 和 libcurl，而CVE-2023-38546仅影响 libcurl。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icWQibEYlpowrLXOAn4fHtC9rhxY1tofgI1qQdxwuJQb24ib7cazN7TQ7jA/640?wx_fmt=png "")  
  
  
**可能是长时间内最严重的漏洞**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icW8sAHjKornNsoibcicfDPrHdvPia4WmlocMR9YagV9G1zqibhhicklAQ2RdA/640?wx_fmt=png "")  
  
  
  
一名维护人员提到，“该高危漏洞可能是很长时间以来最为严重的curl 漏洞。我无法披露漏洞所影响的版本范围，否则识别该问题的准确率非常高，因此我无法提前披露。具体能透露的就是‘最近数年发布的版本’均受影响。我们已经通知了发行版本邮件列表，使成员发行版本能够准备补丁。（在没有支持合同以及合理理由的情况下，其他任何人均无法在10月11日之前获得漏洞详情。）一旦了解之后，应马上行动。”  
  
Tanium 公司的端点安全研究总监 Melissa Bischoping 提到，curl 作为独立工具和其它软件的组成部分均得到广泛应用。Curl 的广泛使用意味着组织机构应当趁此彻查其环境。Bischoping 解释称，虽然该漏洞可能并不影响curl的所有实现，但鉴于该首席开发人员给出的提前通知以及它可能具有的广泛影响，“即使最终并没有那么严重，但将其作为重大事件进行规划是稳妥做法“。  
  
她提到，“作为行业来讲，避免引发恐慌、不确定性和质疑的同时，以准备和补丁管理规划来应对这些‘最糟糕场景’至关重要。我很感激在我们为10月11日将发布的补丁进行全力准备时，curl开发人员能够竭尽所能提前告知并尝试控制随之而来的危言耸听的反应。”  
  
Qualys 公司的研究员 Saeed Abbasi 发布博客文章解释称，libcurl 可使开发人员“在应用程序中增加健壮的数据传输功能，确保软件能够与服务器就多种任务如发送HTTP请求、管理cookie和处理认证等任务进行通信。这使得 curl 成为开发互联和web 应用的重要工具。”  
  
该漏洞为开源安全旋风月划上了句号。白宫主持了由开源安全专家组成的一个论坛，随后发布了关于未来如何应对开源网络安全的路线图。但该会议之后，已有多个开源漏洞引发警报。网络安全和基础设施局 (CISA) 和网络安全研究员提醒称，影响两款热门开源工具libwebp和libvpx的多个漏洞目前已遭黑客利用。谷歌表示已发现未知商业监控软件厂商利用这些漏洞的证据。  
  
上周二，亚马逊Web Services 为TorchServe 用户发布提醒。TorchServe 用于全球规模最大的人工智能模型企业中。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icWQibEYlpowrLXOAn4fHtC9rhxY1tofgI1qQdxwuJQb24ib7cazN7TQ7jA/640?wx_fmt=png "")  
  
  
**SBOM重要性凸显**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMQlib8xW4DWtdQNeLNx139icW8sAHjKornNsoibcicfDPrHdvPia4WmlocMR9YagV9G1zqibhhicklAQ2RdA/640?wx_fmt=png "")  
  
  
  
多名人士表示，最近发生的事件强调了政府推动SBOMs的意义所在。SBOM将有助于组织机构了解所使用软件所依赖的工具。  
  
Bischoping 表示，关于影响Curl 和 libcurl 问题的公布“再次说明SBOM的重要性所在，它可使组织机构找到使用特定组件如curl的任何东西。过去多年来，类似工具中出现类似漏洞的情况并不少见。在行业更好地标准化并默认包含SBOM文档之前，这一问题仍将难以解决“。  
  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511052&idx=3&sn=fb116392e405ae62e6c339117fffdb59&chksm=ea949d66dde31470758b6ee8f9dbecdb67ef6c0c8af277f26b83b60dbac95748d28db787a4b4&scene=21#wechat_redirect)  
[在线阅读版：《2023中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517225&idx=1&sn=8154b433ae2be87ccbae15bc0fb09a00&chksm=ea94b543dde33c55c168c44e830d62b03e9b34ca072871d10156273a3f282cab7ccc42b9b430&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《软件成分分析全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515374&idx=1&sn=8b491039bc40f1e5d4e1b29d8c95f9e7&chksm=ea948d84dde30492f8a6c9953f69dbed1f483b6bc9b4480cab641fbc69459d46bab41cdc4859&scene=21#wechat_redirect)  
  
  
[奇安信入选全球《静态应用安全测试全景图》代表厂商](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516678&idx=1&sn=5b9e480c386161b1e105f9818b2a5a3d&chksm=ea94b36cdde33a7a05cafa9918733669252a02611c222b02bc6e66cbb508ee3fbf748453ee7a&scene=21#wechat_redirect)  
  
  
[《软件供应商手册：SBOM的生成和提供》解读](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511570&idx=1&sn=a8eda02cab19a290202dd91895bd3887&chksm=ea949f78dde3166e104a4d6a2c2c9e1b32d673f6589993a2f2bfb94740bdc6cdc0088dc8c273&scene=21#wechat_redirect)  
  
  
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
  
  
  
  
**原文链接**  
  
https://therecord.media/curl-vulnerabilities-to-be-announced-open-source  
  
  
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
  
