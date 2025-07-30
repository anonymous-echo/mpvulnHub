#  热门开源库 JsonWebToken 存在RCE漏洞，可引发供应链攻击   
Bill Toulas  代码卫士   2023-01-10 17:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRSylJK2k7H6mNqiaS2G6WRaeeK34cLHE6pe9VeOIHYiboAnKB0TMoayZCxFpHMLljzTnz9DnNuFiaqQ/640?wx_fmt=png "")  
  
  
专栏·供应链安全  
  
  
数字化时代，软件无处不在。软件如同社会中的“虚拟人”，已经成为支撑社会正常运转的最基本元素之一，软件的安全性问题也正在成为当今社会的根本性、基础性问题。  
  
  
随着软件产业的快速发展，软件供应链也越发复杂多元，复杂的软件供应链会引入一系列的安全问题，导致信息系统的整体安全防护难度越来越大。近年来，针对软件供应链的安全攻击事件一直呈快速增长态势，造成的危害也越来越严重。  
  
  
为此，我们推出“供应链安全”栏目。本栏目汇聚供应链安全资讯，分析供应链安全风险，提供缓解建议，为供应链安全保驾护航。  
  
  
注：以往发布的部分供应链安全相关内容，请见文末“推荐阅读”部分。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FIBZec7ucCiaWtRttKahE4rd7icPBW6mLiaWubZBfibktxAlCMH6dwLG1225lH4Xo8nmA5ENG7I4o905Qq23icpkHwg/640?wx_fmt=png "")  
  
  
**Auth0 修复了热门开源库 JsonWebToken 库中的一个远程代码执行漏洞 (CVE-2022-23529)。该库已被超过2.2万个项目使用，每个月从NPM上的下载数量超过3600万次。该RCE漏洞影响在2022年12月21日前发布的JsonWebToken 9.0.0以下版本。**  
  
  
  
JsonWebToken 用于很多企业创建的开源项目中，如微软、Twilio、Salesforce、Intuit、Box、IBM、Docusign、Slack、SAP等等。该项目是用于创建、签名和验证JSON Web令牌的开源库。  
  
Auth0 在jwt.io网站上指出，“JSON Web Token (JWT) 是一个开放标准 (RFC 7519)，为在作为JSON 对象的各方定义紧凑独立的安全传输信息方式。由于信息经过了数字化签名，因此是可验证和可信任的。”  
  
该项目由Okta Auth0 所开发和维护，在NPM包仓库上的周下载量已超过900万次，已有超过2.2万个项目在使用它。成功利用该漏洞可导致攻击者绕过认证机制、访问机密信息以及窃取或修改数据。  
  
然而，发现该漏洞的Palo Alto Networks公司Unit 42团队研究人员提醒称，威胁行动者受陷需要攻陷app和JsonWebToken 服务器之间的机密管理流程，使其更加难以利，因此将漏洞严重性下调至7.6分。  
  
  
JWT 机密投毒  
  
  
研究人员在2022年7月13日发现该漏洞并立即报告给Auth0。研究人员发现，威胁行动者可在验证恶意构造的JWS令牌后，在使用JsonWebToken的服务器上实现远程代码执行。该漏洞位于JsonWebToken 的verify() 方法中，该方法用于验证JWT并返回解码信息。它接受三个参数：令牌、secretOrPublicKey 和多个选项。  
  
然而，由于缺少对 “secretOrPublicKey’ 参数的检查以确定该参数是否为字符串还是缓冲区，因此攻击者可发送特殊构造的对象，在目标机器上执行任意文件写。研究人员表示，利用该缺陷以及请求上稍有不同的payload，即可实现远程代码执行。  
  
该漏洞之所以被评判为“高危”而非“严重”级别是因为该漏洞的利用复杂程度高，威胁行动者仅能在机密管理流程中对其进行利用。GitHub 上的安全公告指出，“只有在允许不受信任的实体修改所控制主机上 jwt.verify() 的关键检索参数，才受影响。”  
  
Auth0团队在2022年8月证实称正在着手准备解决方案，并最终在12月21日通过JsonWebToken 9.0.0发布补丁。修复方案包括对secretOrPublicKey 参数进行额外检查，以阻止其解析恶意对象。  
  
鉴于JsonWebToken 是使用极为广泛的开源库，因此该缺陷具有庞大的供应链影响，而在多数项目升级到安全版本前都将继续具有这种影响。虽然该缺陷难以利用，但鉴于潜在目标的庞大数量，不能低估攻击者的利用决心，因此所有系统管理员均应优先应用可用的安全更新。  
  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSZu3o6N7v8IvXlaSpv9pqrC38BdYic1GvE8xzpEraJy9nHYRGk5rCC0dHKEfBr2rC1nJ8gMCDIvIw/640?wx_fmt=jpeg "")  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[在线阅读版：《2022中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513174&idx=1&sn=e474d1ea23ed7cce10e2ae2f872fc003&chksm=ea94853cdde30c2a963cfa00a536764ea55cdee7ba6ef4a7716a28f82a97ca630dc271ee5224&scene=21#wechat_redirect)  
  
  
[在线阅读版：《2021中国软件供应链安全分析报告》全文](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247505380&idx=1&sn=01d2f5af200abc6bb20411ee8f17b6b5&chksm=ea94e48edde36d98f20b66aecf9f359e49226b411872bcea527fcca0a5de018f407415313800&scene=21#wechat_redirect)  
  
  
[PyTorch 披露恶意依赖链攻陷事件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515167&idx=1&sn=24c07a386819db63dc889fa9bfe7b382&chksm=ea948d75dde304635dd31a7b3deeb1ff296b25b6ac462e35546afa8779e3ff455b3cd475dff4&scene=21#wechat_redirect)  
  
  
[速修复！这个严重的 Apache Struts RCE 漏洞补丁不完整](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511361&idx=1&sn=540cad65022d11423a868f977b4fe663&chksm=ea949c2bdde3153d70ed1c43058c67f7e846f30ea1d2f562389edf804ace5c6bf19621f5bf6e&scene=21#wechat_redirect)  
  
  
[Apache Cassandra 开源数据库软件修复高危RCE漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510538&idx=2&sn=1d92fa67b48167800ad01baa90c58cbd&chksm=ea949b60dde312765657b9d469ce2b1b6befbad085737df863891995b40982a6109939fb82b2&scene=21#wechat_redirect)  
  
  
[美国国土安全部：Log4j 漏洞的影响将持续十年或更久](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512944&idx=1&sn=003f4935476be99ce0be8caa3fe086fe&chksm=ea94821adde30b0c5b96de8d9948d479b7a6f59ff1ba75271057b28e17faa26b43c701a5f1fe&scene=21#wechat_redirect)  
  
  
[Apache Log4j任意代码执行漏洞安全风险通告第三次更新](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247509646&idx=1&sn=34bc8208994380969cd89045067150b7&chksm=ea9497e4dde31ef2991a59f30171df1f69368c1951483d97f3de41d81a5717bb03e234491f5d&scene=21#wechat_redirect)  
  
  
[PHP包管理器Composer组件 Packagist中存在漏洞，可导致软件供应链攻击](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514137&idx=1&sn=347691413dc7ecfc2a2dedd365115329&chksm=ea948973dde3006553ae4c52ee22cd9f9c1eb480c80a59e78eaf25d9f9c974ed002d8e053488&scene=21#wechat_redirect)  
  
  
[LofyGang 组织利用200个恶意NPM包投毒开源软件](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514172&idx=1&sn=271b12e7a37da40fb7ddc58a30cf4135&chksm=ea948956dde300402d1d9ef54ea22519931efbfc852b82816c893892b876166c39063af581fc&scene=21#wechat_redirect)  
  
  
[软件和应用安全的六大金科玉律](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514145&idx=1&sn=639a349a140d429c996a51949fec0a92&chksm=ea94894bdde3005d6eeb0e37e7a3f81c6518bdce555fd5d9fff4418c5b305e17c5fb7916cb58&scene=21#wechat_redirect)  
  
  
[美国政府发布关于“通过软件安全开发实践增强软件供应链安全”的备忘录（全文）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514050&idx=1&sn=14f44208b38382e14a3f4562615bedb5&chksm=ea9486a8dde30fbe2b0ef3231a0a73e44579f710c6bede1cd4eb563d0545476d5ef3607ea39d&scene=21#wechat_redirect)  
  
  
[OpenSSF发布4份开源软件安全指南，涉及使用、开发、漏洞报告和包管理等环节](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514034&idx=1&sn=51f02a3110acce0dbd53196876ef1fad&chksm=ea9486d8dde30fce4995e5734ad507e889b4c58c0d3ff8d777f66119f2d5fb3f1c7d0e064726&scene=21#wechat_redirect)  
  
  
[美国政府发布联邦机构软件安全法规要求，进一步提振IT供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513979&idx=1&sn=66625cf062357864cf86053f868d8bb7&chksm=ea948611dde30f0758522e7694b72c9f1abdcbf9c7de8eece909dcdf444e2ce7cf19d357db91&scene=21#wechat_redirect)  
  
  
[美国软件供应链安全行动中的科技巨头们](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513936&idx=1&sn=ffd61a99532c853e13587e17ccb3e9a1&chksm=ea94863adde30f2cbc1141ebad6ae15d7b5ec09ee3c8337db26c9bda2b26c2914cdde4757ffb&scene=21#wechat_redirect)  
  
  
[Apache开源项目 Xalan-J 整数截断可导致任意代码执行](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513963&idx=4&sn=8f7f84190a33593bda1e3d6c86470af6&chksm=ea948601dde30f178f02bdcc42ac15f052526722f31417ec3cc51f2b92cde6a84be7894c8fe8&scene=21#wechat_redirect)  
  
  
[谷歌推出开源软件漏洞奖励计划，提振软件供应链安全](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513721&idx=1&sn=9ccc0511cb8d6c7134eb54700130f1b7&chksm=ea948713dde30e0503874ed6e5ebcd5a90933ef86048fd21466e73431420b799a861f800164a&scene=21#wechat_redirect)  
  
  
[黑客攻陷Okta发动供应链攻击，影响130多家组织机构](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513692&idx=2&sn=9edbf81f8e756e90d33627cdfe3796f3&chksm=ea948736dde30e20a3b8750b3189dd23d0baf268f08e98448ec6421a9d7649d3cfc08f11f960&scene=21#wechat_redirect)  
  
  
[Linux和谷歌联合推出安全开源奖励计划，最高奖励1万美元或更多](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513617&idx=2&sn=4f50589d2631ebc4ee55cbbb21d52fbd&chksm=ea94877bdde30e6db6623e64b233c7a81ddcaa9a50d7211c608a26c1e48cf51a1ee2101991d5&scene=21#wechat_redirect)  
  
  
[开源web应用中存在三个XSS漏洞，可导致系统遭攻陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513307&idx=2&sn=4a99112b9efeb2e33add05f94b1dd1d5&chksm=ea9485b1dde30ca77b26b217f677ed8a3be57d9c8750d39780781015e46520db5185da5bd1dc&scene=21#wechat_redirect)  
  
  
[开源软件 LibreOffice 修复多个与宏、密码等相关的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247513283&idx=1&sn=5fbd02e0f95926cab449829326e0a8a1&chksm=ea9485a9dde30cbf0fb5e64dcbabdcbc1486306bbf9305df01d0f12022f30b84421fe09b167c&scene=21#wechat_redirect)  
  
  
[Juniper Networks修复200多个第三方组件漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512960&idx=1&sn=0df41cf06e3efd8089ec6d6d6b03fc20&chksm=ea9482eadde30bfc407cd490459c7c947bbf2496475946f0379eb8e76c8f4e47f2063742ef87&scene=21#wechat_redirect)  
  
  
[美国国土安全部：Log4j 漏洞的影响将持续十年或更久](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512944&idx=1&sn=003f4935476be99ce0be8caa3fe086fe&chksm=ea94821adde30b0c5b96de8d9948d479b7a6f59ff1ba75271057b28e17faa26b43c701a5f1fe&scene=21#wechat_redirect)  
  
  
[美国国土安全部：Log4j 漏洞的影响将持续十年或更久](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512944&idx=1&sn=003f4935476be99ce0be8caa3fe086fe&chksm=ea94821adde30b0c5b96de8d9948d479b7a6f59ff1ba75271057b28e17faa26b43c701a5f1fe&scene=21#wechat_redirect)  
  
  
[PyPI 仓库中的恶意Python包将被盗AWS密钥发送至不安全的站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512575&idx=2&sn=5af81a53d9263bf10273d86868a77287&chksm=ea948095dde309830949a85914d18a896ce49535f37a9c0cf802e2d84d4dbf264c0e5795396b&scene=21#wechat_redirect)  
  
  
[开源项目 Parse Server 出现严重漏洞，影响苹果 Game Center](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512551&idx=1&sn=a3dc5a12724c0b9b230eedf1455dbf23&chksm=ea94808ddde3099bc99f14a224f4836cc7d9419f056f982dd29238ebf945806f58f2989225bc&scene=21#wechat_redirect)  
  
  
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
**：**  
  
https://www.bleepingcomputer.com/news/security/auth0-fixes-rce-flaw-in-jsonwebtoken-library-used-by-22-000-projects/  
  
  
题图：  
Pixabay License  
  
  
**转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
****  
  
  
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
  
