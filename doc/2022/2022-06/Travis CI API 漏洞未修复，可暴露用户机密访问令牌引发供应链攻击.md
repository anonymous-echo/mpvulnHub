#  Travis CI API 漏洞未修复，可暴露用户机密访问令牌引发供应链攻击   
Ravie Lakshmanan  代码卫士   2022-06-15 17:58  
  
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
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMS57QqGb0E8q1dEGds9lic4hcvtU20F2prcT9iaJaXTlyFxhKvtDC1mV4CqDbOQpDo0uVAWexN9tibCg/640?wx_fmt=png "")  
  
开源持续集成构建项目 Travis CI 的API 中存在一个未修复漏洞，可导致数万名开发人员的用户令牌遭攻击，从而导致威胁行动者攻陷云基础设施，进行越权代码修改并触发供应链攻击。  
  
  
  
Travis CI 是一款持续集成服务，可用于构建并测试托管于云仓库平台如 GitHub 和 Bitbucket 上的软件项目。  
  
云安全公司 Aqua 在本周一发布报告指出，“可从超过7.7亿份免费用户的日志中轻松提取令牌、机密和其它和流行云服务提供商 GitHub、AWS和 Docker Hub 相关联的其它凭据。”  
  
该问题最初在2015年和2019年报告，根因在于该 API 允许以明文形式访问历史日志，使恶意人员甚至“提取此前无法通过API获得的日志。”  
  
这些日志可追溯至2013年1月直至2022年5月，日志数字范围,是4180000到774807924，用于通过API检索唯一的明文日志。另外，分析2万份日志后发现了73000分令牌、访问密钥和其它与多种云服务如 GitHub、AWS 和 Docker Hub 相关联的其它凭据。尽管Travis CI 试图通过显示字符串“[secure]”对API进行速率限制并自动过滤构建日志中的安全环境变量和令牌，但结果仍然如此。  
  
虽然 “github_token” 被混淆，但该令牌的其它20种变量仍然遵循不同的命名方法（包括github_secret、gh_token、github_api_key 和 github_secret）仍未被 Travis CI 掩盖。  
  
研究人员指出，“Travis CI 放缓了API调用的速率，从而阻止了查询 API 的能力。然而在这种情况下，这样做仍然不过。具有技能的威胁行动者可找到绕过这一做法的应变措施。结合通过API访问日志的轻松程度、不完整的审查、访问‘受限制’日志以及速率限制和拦截API访问的弱进程，再加上大量可能被泄露的日志，导致这样一种严重情况。”  
  
Travis CI 回应称该问题是有意设计的，用户应按照最佳实践避免在构建日志中泄露机密并定期修改令牌和机密。  
  
自2022年4月发生攻击者利用Heroku 和 Travis CI 的被盗OAuth 用户令牌提升对NPM基础设施和克隆一些私密仓库的访问权限后，这次的研究成果意义尤为重大。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSZu3o6N7v8IvXlaSpv9pqrC38BdYic1GvE8xzpEraJy9nHYRGk5rCC0dHKEfBr2rC1nJ8gMCDIvIw/640?wx_fmt=jpeg "")  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[RSA | 微软：供应链攻击会越来越严重](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512232&idx=2&sn=d5318dbeb0887bdce3f0a42b60af684f&chksm=ea9481c2dde308d4ba7af531d877751fde2f40dbdf9dab60ad478fad938e9805bcf6738e73dd&scene=21#wechat_redirect)  
  
  
[RSA | ISACA发布全球软件供应链报告](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512232&idx=1&sn=490e8e387ee7617d16c771929ff65ad5&chksm=ea9481c2dde308d4ed1eeb8f3039ae3aba8a2e600920453310b9f38b1399b1ba9daeb6d49ef7&scene=21#wechat_redirect)  
  
  
[奇安信开源软件供应链安全技术应用方案获2022数博会“新技术”奖](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512040&idx=1&sn=7cd8e2d87f73fab31fc52af90d624ccf&chksm=ea949e82dde317940861a08ced505fe54d9a3e5d934a86a09dc887e15908238e3a609484d10c&scene=21#wechat_redirect)  
  
  
[更好的 DevSecOps，更安全的应用](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512117&idx=1&sn=32655307539ef8522fa24a7d2502d01f&chksm=ea94815fdde308499c5c044faf131b08b309d1c267dd6b415b5c54d11005756b529ba706f69f&scene=21#wechat_redirect)  
  
  
[他坦白：只是为了研究才劫持流行库的，你信吗？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511979&idx=1&sn=164ff5ec89fd03cda38673265b221387&chksm=ea949ec1dde317d7050e3abf65a553e3eb4a79f340f96a855b1216fb701369571633486c77dc&scene=21#wechat_redirect)  
  
  
[热门PyPI 包 “ctx” 和 PHP库 “phpass” 长时间未更新遭劫持，用于窃取AWS密钥](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511966&idx=1&sn=77856cc7ec3f5318efb4f18f2a8ddf66&chksm=ea949ef4dde317e2a06b85bfc4ca7d162951708a197fc45a2b94119ddf30e4457c29386705b2&scene=21#wechat_redirect)  
  
  
[从美行政令看软件供应链安全标准体系的构建](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511927&idx=1&sn=953d790ade7a71afee797bc7ed43dc35&chksm=ea949e1ddde3170b29457b8585069b9df881b7507c45e86ddea00fb1a40eba450b168859919b&scene=21#wechat_redirect)  
  
  
[研究员发现针对 GitLab CI 管道的供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511856&idx=1&sn=2acd2eea52dbebe4bca68fd809ab6228&chksm=ea949e5adde3174cfe60fe0e7e66edaca3bc5a90c6d0461a24822d9780d5d48ecdaaf37483b9&scene=21#wechat_redirect)  
  
  
[五眼联盟：管理服务提供商遭受的供应链攻击不断增多](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511780&idx=1&sn=85242245892a794cdb029ebcb6084ebd&chksm=ea949f8edde316983a3bc9b8018aab4e01c1f11761809c95a4fa8942f52e37aad4c9ca6e6425&scene=21#wechat_redirect)  
  
  
[趁机买走热门包唯一维护人员的邮件域名，我差点发动npm 软件供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511765&idx=1&sn=76f935a93e47172f2d372204f9522ae9&chksm=ea949fbfdde316a99025029bc98752c1054bdefb7102d178d7390ea36c5753abd5fcefd1c778&scene=21#wechat_redirect)  
  
  
[RubyGems 包管理器中存在严重的 Gems 接管漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511738&idx=1&sn=3e4c8ab0a54ec620b25047d6fd043b3e&chksm=ea949fd0dde316c6a3cb31463162bcb530954e1a1d222552dd508d94d71fa7285660dda4c0a7&scene=21#wechat_redirect)  
  
  
[美国商务部机构建议这样生成软件供应链 “身份证”](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511687&idx=1&sn=af6f8d4dfc96210b908ef9d6ed040c8e&chksm=ea949feddde316fbb10ddba192a450209a47367c10b3686acd19c92afecfa0a9c2e613e47293&scene=21#wechat_redirect)  
  
  
[《软件供应商手册：SBOM的生成和提供》解读](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511570&idx=1&sn=a8eda02cab19a290202dd91895bd3887&chksm=ea949f78dde3166e104a4d6a2c2c9e1b32d673f6589993a2f2bfb94740bdc6cdc0088dc8c273&scene=21#wechat_redirect)  
  
  
[和GitHub 打官司？热门包 SheetJS出走npmjs.com转向自有CDN](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511687&idx=2&sn=0b3fd53e3b085781c93163b1b927c5b1&chksm=ea949feddde316fb18ee3f415d989562fe86faa7a2c05bfb3ab682e61b814b83ff19eb822d11&scene=21#wechat_redirect)  
  
  
[不满当免费劳力，NPM 热门库 “colors” 和 “faker” 的作者设无限循环](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510002&idx=2&sn=492337bcce98caf9a798668daead3455&chksm=ea949698dde31f8efb3c1cb348ee18baf80e58f8f32c784a36e1dbd3e9a0fef31da331c6ab66&scene=21#wechat_redirect)  
  
  
[NPM流行包再起波澜：维护人员对俄罗斯用户发特定消息，谁来保证开源可信？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511319&idx=1&sn=32793c16c49075815d576cedb430aeb9&chksm=ea949c7ddde3156b7932ea3ffe524fdcbd627b2fe2f5e2280b0c48572b3342ef0f74816b061a&scene=21#wechat_redirect)  
  
  
[NPM逻辑缺陷可用于分发恶意包，触发供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511591&idx=2&sn=1470278e177fc2e94f3009ae19cf57ec&chksm=ea949f4ddde3165b87f25e82eedbf8512850d2c12733e0a849077205bd8792222cb823ccaa84&scene=21#wechat_redirect)  
  
  
[攻击者“完全自动化”发动NPM供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511136&idx=2&sn=1666a56e727766fd72254b952d54ac89&chksm=ea949d0adde3141cd8b544edd6d6df0ee40223df74f7d3753ce9dc03ab805137e120e9482d2b&scene=21#wechat_redirect)  
  
  
[200多个恶意NPM程序包针对Azure 开发人员，发动供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511070&idx=3&sn=a1f87fa84198504a6fd9c1d6d258152f&chksm=ea949d74dde314621963b38e7e1cb232355f633eff9cdb3e6d6989e764ee387af86886c7a87f&scene=21#wechat_redirect)  
  
  
[哪些NPM仓库更易遭供应链攻击？研究员给出了预测指标](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510703&idx=1&sn=3cfe50178ae4fc133d86d53cdf27ec34&chksm=ea949bc5dde312d33eea8144db0c86d205bb53946e32ccdaa0842301a6db67a507ecfd1e5a8b&scene=21#wechat_redirect)  
  
  
[NPM 修复两个严重漏洞但无法确认是否已遭在野利用，可触发开源软件供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509251&idx=1&sn=18a72840cc335f31607d951fc709adf2&chksm=ea949469dde31d7ffe9cb65887f88996ecb8c4da6e4633db84b631269165179ac99fdf8e02c3&scene=21#wechat_redirect)  
  
  
[热门NPM库 “coa” 和“rc” 接连遭劫持，影响全球的 React 管道](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247508946&idx=1&sn=273c58d08a4225306a567cf6a150f40c&chksm=ea9492b8dde31bae31069b432c9e45390f85fe7879335bbd011431cab3fdc0ac9e2efda1af9c&scene=21#wechat_redirect)  
  
  
[速修复！热门npm 库 netmask 被曝严重的软件供应链漏洞，已存在9年](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247502778&idx=1&sn=5ad11d4289635b5d7f945c54cb2129f7&chksm=ea94fad0dde373c66f5c2024246f5c824cac549ac3dcfd85cc67fb238dabca34d7316fef9f65&scene=21#wechat_redirect)  
  
  
[25个恶意JavaScript 库通过NPM官方包仓库分发](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510675&idx=2&sn=a778ae74ffe2f1095ab0f758f7879a3b&chksm=ea949bf9dde312ef3baf0b0e2c892753ec74baa207331ff330547e90e5da4480464074b60f93&scene=21#wechat_redirect)  
  
  
[Pwn2Own大赛回顾：利用开源服务中的严重漏洞，攻陷西部数据My Cloud PR4100](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511095&idx=1&sn=e1f0122f82889cda652d6febbba2879c&chksm=ea949d5ddde3144b2fb52dbbfc2b76961538c21d7e9adc3e02bc2a3b4fb6d592755c393b2cf6&scene=21#wechat_redirect)  
  
  
[开源网站内容管理系统Micorweber存在XSS漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511095&idx=3&sn=adbaf85a2b52fa28271d8650cc9f5e3a&chksm=ea949d5ddde3144b570cbe1d529895ae54cb07f1f1db4b3f8eb26622905360a3b6aa62e5c2b5&scene=21#wechat_redirect)  
  
  
[热门开源后端软件Parse Server中存在严重的 RCE ，CVSS评分10分](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510991&idx=2&sn=1396eb76de81d7c7c1a252c7028381fe&chksm=ea949aa5dde313b398c64c3399132d91861cd3ec85bc341afbcfc8899e6d3818f2c52bb846db&scene=21#wechat_redirect)  
  
  
[开源组件11年未更新，严重漏洞使数百万安卓按设备易遭远程监控](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511504&idx=2&sn=04504363458ec7eae8089dbfb498d827&chksm=ea949cbadde315ac5c9bd2f40a6f192b3250198f157ae151d9aa59e0f29ce6b3f21dd2118763&scene=21#wechat_redirect)  
  
  
[开源工具 PrivateBin 修复XSS 漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511433&idx=3&sn=ff04084cd337034fbdf95f2eb572c65a&chksm=ea949ce3dde315f54aac997e6b2fa73ed091ef780a4381e169502f00c9227d9bc2518f543d05&scene=21#wechat_redirect)  
  
  
[奇安信开源组件安全治理解决方案——开源卫士](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510243&idx=1&sn=5c1b121cfec855804ee3cca0e672f224&chksm=ea949989dde3109ff44630e253129af120586e9408978956528390758d833e1bc1d4d2388d7c&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/unpatched-travis-ci-api-bug-exposes.html  
  
  
题图：Pixabay License  
  
  
  
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
