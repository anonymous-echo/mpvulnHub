#  Palo零日漏洞凸显面向互联网的接口风险不断上升   
原创 何威风  祺印说信安   2024-12-12 16:01  
  
> 最近的报告证实，针对 Palo Alto Networks 的下一代防火墙 (NGFW) 管理接口的严重零日漏洞正受到积极利用。虽然 Palo Alto 的快速建议和缓解指南为补救措施提供了起点，但此类漏洞的广泛影响需要全球组织予以关注。  
> 针对面向互联网的管理界面的攻击激增凸显了不断演变的威胁形势，并迫使组织重新思考如何保护关键资产。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rTibWNx9ARWmsCN6k2swgr96MYNF8RS2ZJzRDIhVKib7a4QXERmupjwkCeSC13XM9sGqiajhGDeiaVoYx3I54reia6Q/640?wx_fmt=png&from=appmsg "")  
## 谁在利用NGFW零日漏洞？  
  
  
截至目前，人们对Palo Alto NGFW零日  
漏洞的积极利用者知之甚少。  
Palo Alto已观察到针对有限数量的互联网暴露管理接口的攻击，但这些活动的起源仍在调查中。  
  
由于此类漏洞通常涉及高价值目标，因此人们一直猜测  
有国家支持或出于经济动机的团体参与其中。研究人员注意到，暗网论坛上有人出售相关漏洞，这表明这种威胁可能影响范围更广。  
## 针对管理界面的趋势  
  
攻击者越来越多地利用先进的战术、技术和程序 (TTP) 来攻击暴露在互联网上的管理接口，通常可以绕过传统防御措施。这些接口提供对关键基础设施的管理控制，对于寻求获得未经授权的访问、操纵配置或利用特权升级漏洞的对手来说，它们是一个有利可图的目标。  
  
最近的数据  
显示了一个令人不安的趋势：网络犯罪分子越来越擅长识别和利用此类漏洞，尤其是在组织未能遵守最佳实践的情况下。Palo Alto NGFW 零日漏洞的发现增加了越来越多的漏洞，这些漏洞被积极利用来攻击这些高价值的入口点。  
## 降低风险：什么有效，什么无效  
  
随着Palo Alto Networks不断开发补丁和威胁预防更新，组织必须果断采取行动，限制其暴露。从历史上看，保护管理界面依赖于以下基本措施的组合：  
1. **限制对受信任 IP 的访问******  
这仍然是限制暴露的基石。通过仅允许从特定的受信任的内部 IP 地址进行访问，组织可以显著降低未经授权访问的风险。Palo   
Alto  
和其他网络安全专家强调，这项措施是最有效的临时解决方案。  
  
1. **网络分段和使用跳转服务器**  
  
将管理接口  
与直接互联网访问隔离，并通过安全跳转盒路由管理流量，增加了一层关键的保护。攻击者需要对跳转盒进行特权访问才能继续进行，这使得利用变得更加困难。****  
  
  
1. **威胁检测与预防******  
利用  
威胁情报  
和预防工具，例如配置为阻止已知攻击特征的  
入侵检测系统  
和防火墙，可以提供针对新出现的威胁的实时保护。  
  
1. **多因素身份验证****(MFA)******  
强制执行管理访问的 MFA 有助于降低风险，即使登录凭据受到泄露。  
  
然而，一些传统方法在复杂的攻击方法面前显得不足：  
- **单独的静态 IP 限制：**  
虽然 IP 限制至关重要，  
但如果攻击者破坏受信任的 IP 或利用同一网络内的其他漏洞，则  
IP 限制可能会受到破坏。  
  
- **过时的软件和遗留系统：**  
许多组织仍在运行没有对现代安全功能提供强大支持的遗留系统。这些系统通常是防御高级 TTP 的最薄弱环节。  
  
- **过度依赖外围防御：**  
仅仅依赖  
防火墙等  
外围防御，而不实施  
  
零信任  
原则，会留下攻击者可利用的漏洞。  
  
## 威胁暴露管理  
  
管理漏洞不仅仅是修补和基本的强化措施。组织应采取主动的方法来识别和修复潜在的漏洞：  
- **资产发现和持续扫描：**  
定期扫描以检测面向互联网的接口并绘制  
攻击面  
至关重要。例如，组织可以利用扫描工具来识别错误配置或无意中暴露给互联网的接口。  
  
- **漏洞管理**  
：并非所有漏洞都具有相同的风险级别。身份验证绕过或远程代码执行漏洞等严重漏洞应在补救措施中优先考虑。  
  
- **事件响应准备：**  
考虑到零日漏洞的利用速度，制定强大的  
事件响应  
 计划可确保在发生漏洞时快速遏制和恢复。  
  
## 对组织的启示  
  
面向互联网的管理界面的利用清楚地提醒了主动安全措施的重要性。虽然 Palo Alto Networks 等供应商通过补丁解决漏洞，但组织必须立即采取措施减少攻击面。限制访问、部署分层防御和采用持续的威胁暴露管理实践对于保持领先于对手至关重要。  
  
— **欢迎关注 往期回顾**  
 —  
  
[精彩回顾：祺印说信安2024之前](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103882&idx=1&sn=fe68b43898a872f40e66a8cdb720d7d7&chksm=8bbccef3bccb47e5bd52249ff6490fe17df9696568053776e4124ef70d790a5ed06f2d3c6809&scene=21#wechat_redirect)  
  
  
[230个网络和数据安全相关法律法规规范文件打包下载](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105479&idx=2&sn=1f51edc838bc6dbe991b184178d6d0ac&chksm=8bbcc13ebccb4828eb26b14990d39068d4d1e7c3f43989dd0ade728567228036ef8f12f55208&scene=21#wechat_redirect)  
  
  
[单位高层领导参与网络安全不应该只是口头说说](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109701&idx=1&sn=c71fdd6f2c197fa7fd1bd40b1539be2e&chksm=8bbcd1bcbccb58aad9294bb2e2079582fecf40b6fb2646e12026f017a4453a854cfea1ed7705&scene=21#wechat_redirect)  
  
  
[党委（党组）网络安全工作责任制实施办法](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109696&idx=1&sn=18d149ee98579471afff5c7eb056d2ef&chksm=8bbcd1b9bccb58af141e591b7a9814f6c1c01413f8fc0472515b03f50356444026f10116793a&scene=21#wechat_redirect)  
  
  
[“两高一弱”专项下，谈合规下的弱口令](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110057&idx=1&sn=b34aa34b68219a34d6e7f3ed97c1a403&chksm=8bbcd6d0bccb5fc6e0f1fba87f40441349b1e1ae98418eec649d08bcb0dd6c7676f76ba10b05&scene=21#wechat_redirect)  
  
  
[网络被黑？还看“两高一弱” ，原来是不履行网络安全义务惹的祸](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110738&idx=1&sn=8a1eb107a95fe88afd3ee0acbc33ac18&chksm=8bbcd5abbccb5cbd0ac20564bbc40772e25befab23149eae9bb5ec338d9fe6654e7c32519c63&scene=21#wechat_redirect)  
  
  
**>>>网络安全等级保护<<<**  
  
[网络安全等级保护：等级保护工作、分级保护工作、密码管理工作三者之间的关系](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652098579&idx=1&sn=56da5aedb263c64196a74c5f148af682&chksm=8bbcfa2abccb733ca8dd898d7c0b06d98244ca76bd7be343482369fa80546554cced706fa74c&scene=21#wechat_redirect)  
  
  
[1994-2024等级保护30年法律法规及政策发展历程概览](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112745&idx=1&sn=dda5898c1bd559cce3d341bf5ff2eb57&chksm=8bbb2d50bccca4463d2983d1415b6df87e918821bdbb0cef54424e07a10777344d37266e1ad9&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：等级保护的概念](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112444&idx=1&sn=3181f897a9942c6a27b80d0ea85c4888&chksm=8bbb2c05bccca513948ef90d29c8dc8f539a028afe39ae4739b248d302673e34310b061240f2&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：等级保护工作的内涵](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112503&idx=1&sn=f49457cf83c541343052ea45345e26bb&chksm=8bbb2c4ebccca55823cca4a770a9c5d7c8029e2f8dba152017a504662cc2e0ff9e162af31bd3&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：开展网络等级保护工作的流程](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112523&idx=1&sn=fe78c637d17b7962ee5242527f17165a&chksm=8bbb2cb2bccca5a4529f0f7247169fedd364d9dc137951fb5f37f96f1de3cdc254c4d65b4058&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：贯彻落实网络安全等级保护制度的原则](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112572&idx=1&sn=9956660c62f0b36ceaa5137e67e95380&chksm=8bbb2c85bccca593c23a64f189d7cc91a5a875ff15902db0048d9c7740ff71aab4361a986e23&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：开展网络安全等级保护工作的法律依据](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112652&idx=1&sn=d80fc403b02b2030a795300ff9be7e05&chksm=8bbb2d35bccca423db6c39b115e96241467d614277be1dd91a8affb7b66a108447077af2e9ab&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：开展网络安全等级保护工作的政策依据](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112671&idx=1&sn=8bcd80cbcd05c76f98548bf9dea9446e&chksm=8bbb2d26bccca4307cedf5c8dfea5820202529214d22072f34674b377ee29d1a4788d94b87b0&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：开展网络安全等级保护工作的标准依据](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112727&idx=1&sn=9c7892e1501695d87579f0802d63dd11&chksm=8bbb2d6ebccca47802156673d343ee2b741ebf793c0813d6be7ee9362260e770cf102f0a9abd&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：等级保护工作从定级到备案](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112835&idx=1&sn=a9b09fdc71a933c2bb0168ed68676a4e&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：网络总体安全规划很重要](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112849&idx=1&sn=7bf737addde1144cae296600417add8e&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：一定要做好网络安全运行与维护](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112961&idx=1&sn=a7439c617ed79f6996b28066e7e4f923&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：应急响应与保障是法定要求](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652113101&idx=1&sn=32e643ef6dd1a938d3c1f2de621da53c&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：如何正确处理终止的等级保护对象](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652113141&idx=1&sn=d2ac3c31d4a3eee0793df991f3cafb91&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：政策与技术“七一”大合集100+篇](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108174&idx=1&sn=455ba77fd3a186100820b8d180fcd742&chksm=8bbcdfb7bccb56a17cc1d42b93895ecfb0b51a9417a5f63fc4482567c73fb46be0418d43b567&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：安全管理机构](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109115&idx=2&sn=4f1af46e726949f4d038bde63c2362ef&chksm=8bbcd302bccb5a14b71aa1c242c14636fb3f4d37710e18db76bdcb91ab74a3aaa412f1226c7f&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：网络安全事件分类分级思维导图](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109100&idx=1&sn=b0a47754b6df3f02f38daf7b7e23eb74&chksm=8bbcd315bccb5a032afa3441f65dfc391355834fbdf574ae6bce3caf42fa90766d80de1d6e84&scene=21#wechat_redirect)  
  
  
[网络安全等级保护：明确测评双方的责任从了解测评过程指南开始（思维导图下载）](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111773&idx=1&sn=1441cfedec441d13dff9e989012e9dd0&chksm=8bbb29a4bccca0b2b266820ba86269a3baef47022ee3776e2521ad837991d1a6508f3c22bbad&scene=21#wechat_redirect)  
  
  
**>>>数据安全系列<<<**  
  
[数据安全管理从哪里开始](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103384&idx=1&sn=391073e6109ff105f02be9029e01c697&chksm=8bbcc8e1bccb41f7fe478a3d22757d61f10dcf42548c1c02c0579b8f161277e527ba98ccb542&scene=21#wechat_redirect)  
  
  
[数据泄露的成本：医疗保健行业](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109243&idx=2&sn=cd2405090c5d26f97c602946d3f8eea1&chksm=8bbcd382bccb5a94114aa6fda3d3ba0629eb958a6b7a9711889d552a029462d64ac97e3a46da&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据安全策略规划](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104021&idx=1&sn=7f80bb27ce6ad7c9debe83c172ff9f73&chksm=8bbccf6cbccb467a0971b9de4a8b14851c2666ad6934a88b8324a1ffc4b5cf5109cbc3976697&scene=21#wechat_redirect)  
  
  
[数据安全知识：组织和人员管理](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109274&idx=1&sn=7be5a754d4667aa47c46b16f1b4d0579&chksm=8bbcd3e3bccb5af52e3d908edb77e57505315689950e24754a3152a80528ab6745788a318ec3&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据库安全重要性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104183&idx=2&sn=f2a98256b0497ce3a99c0ad30223bf40&chksm=8bbccfcebccb46d8aac9f8a5c8d1f46061ca61ad69b3a61d52d3dc614e1e18ae65d982a5574b&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据整理与数据清理](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105810&idx=2&sn=97ff4a8d1f2c7f3f6a0252f4df58b20b&chksm=8bbcc66bbccb4f7d058c46bc9c67d34c2042993f2ad32c7732d9816f8dfa4abb7e10f0fd307f&scene=21#wechat_redirect)  
  
  
[数据安全知识：什么是数据存储？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108099&idx=1&sn=0ccf837988c4dc590d1fd9d634d0c02b&chksm=8bbcdf7abccb566cfa3ab37a304567fbca0833291b7f0cb99d36cdebd9d1f58ae72d03d82cd2&scene=21#wechat_redirect)  
  
  
[数据安全知识：什么是数据风险评估？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652106123&idx=1&sn=5f1a4c50b11a1155b22e8d5f01f5c6ca&chksm=8bbcc7b2bccb4ea46d1666254d8f027d2e68d4f38a621f4d7cc05d398f342a0eabeecb29be2e&scene=21#wechat_redirect)  
  
  
[数据安全知识：如何逐步执行数据风险评估](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652106385&idx=1&sn=a71f4b9827f82daff6b5ff61d1f66d2d&chksm=8bbcc4a8bccb4dbe639df71411c12a859b26da7b4fd84b544effc20d98426fd628af59a8c868&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据风险管理降低企业风险](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652106372&idx=2&sn=9ad51e532256b7fbe3aefdf7ec804777&chksm=8bbcc4bdbccb4dabb0cd03a18862dd076ebd798a0bd2aae82a5916e8f9a04b53e5fcd344feb6&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据整理与数据清理](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105810&idx=2&sn=97ff4a8d1f2c7f3f6a0252f4df58b20b&chksm=8bbcc66bbccb4f7d058c46bc9c67d34c2042993f2ad32c7732d9816f8dfa4abb7e10f0fd307f&scene=21#wechat_redirect)  
  
  
[数据安全知识：什么是数据安全态势管理？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105525&idx=1&sn=8625752fb73b4da258b7df177ff8709d&chksm=8bbcc10cbccb481a1b0a68f1061dd2fdda08d2e58974c0fb3fd2c90c9fa77e0641ab814399b2&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据库安全重要性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104183&idx=2&sn=f2a98256b0497ce3a99c0ad30223bf40&chksm=8bbccfcebccb46d8aac9f8a5c8d1f46061ca61ad69b3a61d52d3dc614e1e18ae65d982a5574b&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据库安全威胁](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103736&idx=2&sn=6d70e9d5690b4e3748460d641e14fce8&chksm=8bbcce01bccb47177fce9597fb30e8a27e00a9683e6afbcfb2ea7128a424504ff24af8aa54cc&scene=21#wechat_redirect)  
  
  
[数据安全知识：不同类型的数据库](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103688&idx=1&sn=9377838e11b62f5d73aa1dbda22ec178&chksm=8bbcce31bccb4727c19ada8cdf5d571227e363447987209eb77f4f07e240b1cd263c2de8a547&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据库简史](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103686&idx=1&sn=abcfc1080a7641d41607cca4dc0fab1d&chksm=8bbcce3fbccb4729926a8249ec3bb0344a59268b7af49a68100c03839ace2c6ea59228e68c75&scene=21#wechat_redirect)  
  
  
[数据安全知识：什么是数据出口？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103679&idx=1&sn=f23569ddbc6e5b5b39b307401a53a7f4&chksm=8bbcc9c6bccb40d06ee30f3e73257c08ff61d5aff33040f9a08513473a1f9619f285a531ef42&scene=21#wechat_redirect)  
  
  
[数据安全知识：什么是数据治理模型？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103450&idx=1&sn=ce981cd32e6966e5bfd08e0e85ac6528&chksm=8bbcc923bccb4035b5bd145b2941e0f096cb26f0448a3c5f7fd1bf0652507f2470a33ea26fde&scene=21#wechat_redirect)  
  
  
******>>>错与罚<<<**  
  
[警惕风险突出的100个高危漏洞（上）](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110660&idx=2&sn=f73b70334bbbfd41e947196421c0e48e&chksm=8bbcd57dbccb5c6b8b4e1d2fb983c38b5d8b5b4eac9fa5d962a394986b52c236ffd52e98900c&scene=21#wechat_redirect)  
  
  
[警惕风险突出的100个高危漏洞（下）](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110692&idx=1&sn=07a2e458a81bf5e171c012ec2d390747&chksm=8bbcd55dbccb5c4bb497a3f138646541862342730a91e07cd87ee057ed895463fc79889d7f9a&scene=21#wechat_redirect)  
  
  
[警惕“两高一弱”风险及安全防护提示（全集）](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110867&idx=2&sn=6f1237fc1d4b4a96274a7ac32d30dd48&chksm=8bbb2a2abccca33c14387b6dab727657d29828f1d345e5a5ed6916c551c79caa46227b70e98f&scene=21#wechat_redirect)  
  
  
[不履行网络安全保护义务是违法行为！多家单位被通报！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110660&idx=3&sn=d76fcf3f3b2460f12788131b24bd07bb&chksm=8bbcd57dbccb5c6b54706e7a7b969bec42b8f938b5e3288c4f66181a6761ec2b2a2c6e762258&scene=21#wechat_redirect)  
  
  
[因侵犯公民个人信息罪 深圳一人被判一年三个月 售卖他人求职简历](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110562&idx=2&sn=c6a1c5f1a8ca72cee2275e12c04e3da7&chksm=8bbcd4dbbccb5dcde3df4fcf8c145d2ea32ed8cc9661e41cfc3e81b30c2b4bc9044290932a2f&scene=21#wechat_redirect)  
  
  
[公安部网安局：河南开展整治网络谣言专项行动 查处造谣传谣3000余人](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110555&idx=1&sn=5ed0b638c02610d74ea55c6ea395fa6d&chksm=8bbcd4e2bccb5df45946baa11ef66ff7fa78857a8860732bc1648d3f724cd94b1b375db31455&scene=21#wechat_redirect)  
  
  
[四川遂宁公安公布10起涉网违法犯罪典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110543&idx=1&sn=82fb911e67140dc4c3bc2f718b51b2f2&chksm=8bbcd4f6bccb5de02ac699120a6846b52769fc3b556d5c714989155da6b0112602f945efdca9&scene=21#wechat_redirect)  
  
  
[276人落网！河南新乡警方摧毁特大“网络水军”犯罪团伙](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652107934&idx=1&sn=3fdd7afb3d6a3f78a89264fee3d0b20f&chksm=8bbcdea7bccb57b19ec50b56f4d52ea88256f018bdaf52e71b0bb69c04b43b657068fc8873d3&scene=21#wechat_redirect)  
  
  
[重拳出击严打涉网犯罪 海淀警方守护网络清朗](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108593&idx=1&sn=8e93b447968d40bf565560c46745345c&chksm=8bbcdd08bccb541e2f8b10b6b48906b74b32ac105ed15d32e2b09bd9a817a62669089a4b6eee&scene=21#wechat_redirect)  
  
  
[网警@同学们 暑期这些兼职不能做！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108584&idx=1&sn=27619dc24ce7fb3ea7d6c3f6583c8985&chksm=8bbcdd11bccb5407929b19d23b46d46660f67a3aa3403573c4f719b853bf5cac1bea3d874a76&scene=21#wechat_redirect)  
  
  
[非法出售公民个人信息 网站经营者被判三年有期徒刑](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108478&idx=1&sn=7141f5a94125cd7197f42ad9ec90d049&chksm=8bbcdc87bccb5591b67768e99a087cf7ed7dcf649de05aae58f07145ad1f1ebb10b19811fa4a&scene=21#wechat_redirect)  
  
  
[超范围采集公民信息，违法！鹤壁网警出手](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108457&idx=1&sn=63410ada1542c292aef408d9f19a406e&chksm=8bbcdc90bccb558613ccf77045115cadee03018421cc7d27e0c4d3539fc0e417f0bf127b0ffb&scene=21#wechat_redirect)  
  
  
[一公司高管为泄愤攻击智慧停车收费系统，致上千家停车场无法自动抬杆](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108431&idx=1&sn=e956b5e0330d1ac42c0970a8221cbd2d&chksm=8bbcdcb6bccb55a02ad83b6f9d4e0982a66aa2c68f190784d4872d96ca575491f8b6cbb395c2&scene=21#wechat_redirect)  
  
  
[重庆某国企因网安责任人履职不到位被约谈](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108391&idx=2&sn=3b7ecd3285d400cb121a1c2b4a315f77&chksm=8bbcdc5ebccb554840f9a3a4c1cf6aaa0232f99264fc985c73680c3eba4ac9620c172430c96d&scene=21#wechat_redirect)  
  
  
[因违规收集使用个人信息等，人保寿险宁波分公司被罚32万，4名责任人同时被罚](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108384&idx=1&sn=b4d530f625ded16386039925ec895b93&chksm=8bbcdc59bccb554fb14966a1dbb45cadd2bea2262ef55d24fd8b3e9e5823d62f85cf9a665ebd&scene=21#wechat_redirect)  
  
  
[回顾长沙市三个区网信开出首张罚单的不同时间和处罚单位类型](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652108218&idx=1&sn=bb9a9d86f84190165657fe632a20a6fd&chksm=8bbcdf83bccb56957221b54507e3e3d2c5175c3c03e446c1b6f21ea0f5996d63e9823c40bea1&scene=21#wechat_redirect)  
  
  
[上海4人被判刑：5元掌握明星偶像行程？贩卖明星信息4人被判刑！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652107594&idx=1&sn=ee06d83cfaa8707d854bc55f40390712&chksm=8bbcd973bccb50656351a887d05ff7fe1903fe9b047c326c234ecb35b30ca16fe9bc9de18fb3&scene=21#wechat_redirect)  
  
  
[假期内，网络主播直播约架？郑州警方迅速控制，刑拘十人！网络空间不是法外之地！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652107500&idx=1&sn=e7164b1ec2e7b3c81ef786c8062ea90d&chksm=8bbcd8d5bccb51c37b36fb9dae5edc4cb7eb7f37c0676aed9e03349369fe14db5b5414603066&scene=21#wechat_redirect)  
  
****  
  
[网安局：拒不履行网络安全保护义务，处罚！事关备案！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652107522&idx=1&sn=4843f7b72a7a7b1da458c4f240947dc2&chksm=8bbcd93bbccb502d8bc6a2291e7c5a08798ae79d5cae3037de990332dfe0f9243add5e39e32b&scene=21#wechat_redirect)  
  
  
[网络水军团灭记：“转评赞”狂刷单 上百人“网络水军”团伙落网](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652107516&idx=1&sn=117d1be3f2c7b4057e6a60d0ab48f29d&chksm=8bbcd8c5bccb51d3aad4a7cf41cbd73e2c6fb01a152de00603cfbeb5ce7aa31ca62c95653cbc&scene=21#wechat_redirect)  
  
  
[北京多家公司因不履行网络安全保护义务被处罚！“两高一弱”仍然是安全隐患重点](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104010&idx=1&sn=0ddfdc41a52d235c99269b784b7858fa&chksm=8bbccf73bccb4665d0c29f8067b90e0e9b48894d2d4bbb9da98e64218efa47e36c32034a4775&scene=21#wechat_redirect)  
  
  
[关于“近20台服务器“沦陷”，3.54亿条个人信息被盗”一点点浅析](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652107485&idx=1&sn=b921658e6fc54b0e03c424060bb195c2&chksm=8bbcd8e4bccb51f23d9e791898e7242435c9eb86a9466eb14696154f453e909df4ca99058048&scene=21#wechat_redirect)  
  
  
**>>>其他<<<**  
  
[2023年10佳免费网络威胁情报来源和工具](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103402&idx=1&sn=80a1ee98453d96a6f2304272d2a6b33e&chksm=8bbcc8d3bccb41c5fe204b9933fbded47cd14612e3101111b2f806d8a136a61ff27577dfd765&scene=21#wechat_redirect)  
  
  
[重大网络安全事件事后工作很重要](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109243&idx=1&sn=66ebd9e0cd7aaed3967e7892e97411ec&chksm=8bbcd382bccb5a94ea5827868c3b4f53720df5924228b6d7e86bdb3846af2005a791c988dc57&scene=21#wechat_redirect)  
  
  
[默认安全：对现代企业意味着什么](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109171&idx=2&sn=ccd124eea257169076752301ad771bfc&chksm=8bbcd34abccb5a5c65ecc8e34939a28c986df836538b42a371a98ab4bb86ffaf6745a614cd30&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是事件响应？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109115&idx=1&sn=af5883cf9e70ccedd3b149ec88083f63&chksm=8bbcd302bccb5a14c517e489c94f479fe506653555319e7afb7ac497f1b18f931fc112acca05&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是攻击面？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109689&idx=1&sn=61962a0441d69a6a45bafa0858c73ac3&chksm=8bbcd140bccb5856dcc218be44459f8ec2bb83155b9245135aa2e0660d04f26bf64a2032334d&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是访问控制列表 (ACL)？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652109981&idx=1&sn=3b95eb9a12e7cd3a9db4a8fb90c3f298&chksm=8bbcd6a4bccb5fb2d18a5315364285c9368181762a07181abbdc87be85e92274d405c6b8148a&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是访问管理？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110001&idx=1&sn=e18dd441809b6634de4821a0d619e898&chksm=8bbcd688bccb5f9ea001b8fb253e92f929ec2b1441f7a9d86e1bb8a6a0cbf3010d97c4d41116&scene=21#wechat_redirect)  
  
  
网络安全知识：什么是访问矩阵？  
  
网络安全知识：什么是账户收集？  
  
网络安全知识：什么是工业控制系统 (ICS) 网络安全？  
  
网络安全知识：什么是暴力攻击？  
  
网络安全知识：什么是安全审计？  
  
网络安全知识：什么是分组密码？  
  
[网络安全知识：什么是僵尸网络？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110814&idx=1&sn=8b8643f27090517cd38b7bdfca106b64&chksm=8bbcd5e7bccb5cf1de02c7a139dcf27e3772926c33a2c799f50f34bc283334265f6d1a55d314&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是非对称加密？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110867&idx=1&sn=20f07912999089d4b0133c7a1e5cec82&chksm=8bbb2a2abccca33ce3f700baf9cd4c96168180228810626a777017d55479809aad038e0e2f55&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是边界网关协议 (BGP)？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110952&idx=1&sn=ac6937a832634777a5c0480e7b847e5c&chksm=8bbb2a51bccca347a51a6e3ae6b002b162026c6d3cceb89be97ffc4d7abf9cb1175be02c72ab&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是缓冲区溢出？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110978&idx=2&sn=864c593d89fd0c500cabf040fc6d254e&chksm=8bbb2abbbccca3adcb1bf265e874de8fe2f622998c81a423e744d94ba5fc5efc46d4299707a2&scene=21#wechat_redirect)  
  
  
[网络安全知识：网络安全中的EDR是什么？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111008&idx=2&sn=e68f898907e90b7d12e4d6c89dd053f2&chksm=8bbb2a99bccca38f6ebc8b3e3df8ee219a839137a47c4d9321357aa7924c539eff63a681a932&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是身份验证？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111116&idx=1&sn=f18dfbd3df26e039176ca2a89538cc99&chksm=8bbb2b35bccca223a87356ec689522b735b67f210d0909afc7ad0947123e7a28fa81c292b517&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是勒索软件？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111162&idx=1&sn=2bb5e90d61e923c6f8bda9daaf2f4e22&chksm=8bbb2b03bccca2157560e7f883da20ec97ea1f28f4acac53d2e1f3cb70fca6a6bb635c5f9b28&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是授权？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111403&idx=1&sn=dfc2ab6b8f3b16c1b396f4e9ecd46d32&chksm=8bbb2812bccca104d3a5e98cfda7df39998f99aa684e8e1d19f0ff3b1ccbd2c5fefa1f631d0f&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是自治系统？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111408&idx=1&sn=64fd103eabd6f3385cbd7d1f5753e1ba&chksm=8bbb2809bccca11f0912cdabfc8cdbaa9e088e3fff648bdc784020ebc60fb113f4a3854ce528&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是蓝队？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111435&idx=1&sn=76a6e146976c771efbd33d18711aeaed&chksm=8bbb2872bccca16471c5a11ef0ed85b961ea13f79840e6480868f5a2e07bd92f0b5b730c9858&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是Bind Shell？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111434&idx=1&sn=6abb4da55ace854504634b91c5d03d0d&chksm=8bbb2873bccca1658009cced3c8eb6e33d8fe70b92b21c909d19e165f34984370ce685464795&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是安全网关？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111461&idx=1&sn=49f35ce8e8c4a514021230d6ff71df63&chksm=8bbb285cbccca14a366dfa79b28eade1946697ad6e21d56c4779326d5c64bf3b19e8da17c334&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是蓝队？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111467&idx=1&sn=535dc711614409556111ae5f8b934fb1&chksm=8bbb2852bccca144b52292ba3a6db4c0d1bc30e994e44436b32646ad30155e32b093bc8896a4&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是防病毒产品？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111499&idx=1&sn=af21f8e561e6dcb9054731c9f6eeeb44&chksm=8bbb28b2bccca1a48d49ba0274f13bce414011c0d5c5b0343e4fcd44a6b8084c360497b3196f&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是横幅抓取？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111530&idx=1&sn=b96c0cb4c526efa421140f1969054370&chksm=8bbb2893bccca185b9d74221dda8928675234c7dca7a7509ada71f75d12725c09f24556f8ce5&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是堡垒主机？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111569&idx=1&sn=682b9fd72de2345add63f32cb03a9594&chksm=8bbb28e8bccca1fed6e96e303693f15d2fca5af53104c4501266138326ea8dcd814d567dc383&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是引导扇区病毒？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111623&idx=1&sn=d08c3a5d6a56d19ab09efc23f931f591&chksm=8bbb293ebccca0281f91f4b4841fd0322ccf054b00884bf4d5e781ad7b87af2e748663447bb3&scene=21#wechat_redirect)  
  
  
[网络安全知识：计算机网络中的桥接器](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111663&idx=1&sn=988871cc851be902d4a522742f3aa74f&chksm=8bbb2916bccca00079ad347eb1edb3b05e89f992029a0578d2bee3f35d7f57ded335938a998d&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是广播？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111804&idx=1&sn=bfebf50ec42eb80bb514fcd58b4118f7&chksm=8bbb2985bccca093779606eda8be3e7d8612cff4875b2d53b1bba8c7b824b8026cdc1a94c3b3&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是业务连续性计划？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111861&idx=1&sn=6422e5fff3d9f15538ad1f584c9d64a7&chksm=8bbb29ccbccca0daf5a36e2b9ecfaadbcce7536e764d12c94cb11f603b3dd08d024fe0a31ee4&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是基于证书的身份验证？](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652111903&idx=1&sn=4fff383f27b653414bf334d894aff2f2&chksm=8bbb2e26bccca730f90859d9ce0095bf42192f937c3f8614cb703804cc21560ecb39aeb19315&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是CIA三要素 (机密性、完整性、可用性)？](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112578&idx=1&sn=8e236abf1aea3b6de7d80234f58af968&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是补丁管理？](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112388&idx=1&sn=5799596c81726a761009ffb714455ce8&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是跨站请求伪造？](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112614&idx=1&sn=dbd3cfbe542f6a9fb8fcaeeec8259865&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是基于域的消息认证、报告和一致性 (DMARC)？](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112775&idx=1&sn=1c689515720840a3cf71ae817b509550&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是拒绝服务（DoS）攻击？](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112824&idx=1&sn=c9661d1460b86c876ce439cb859747c8&scene=21#wechat_redirect)  
  
  
[网络安全知识：什么是端到端加密 (E2EE)？](https://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652112887&idx=1&sn=2694af862803bf528803af15ad6eda36&scene=21#wechat_redirect)  
  
  
[将人类从网络安全中解放出来](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110078&idx=1&sn=9b6012acb2808e9979623b819070c6e3&chksm=8bbcd6c7bccb5fd1b188fdbcaffeab331d050f1f48a14a5a3d150c1d2933c7f644b0716b4cda&scene=21#wechat_redirect)  
  
  
[人，是造成网络安全问题的根本原因](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652110057&idx=2&sn=59ec8be4eb16065bba92c423f443e75b&chksm=8bbcd6d0bccb5fc6b550d4baa70646f94e2b2bb5f3d8639a4f8ecca6fdf314c85e32c635f23c&scene=21#wechat_redirect)  
  
  
****  
