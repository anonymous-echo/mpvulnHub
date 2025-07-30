#  CISA、FBI要求消除路径遍历漏洞影响   
何威风  河南等级保护测评   2024-05-08 00:00  
  
**美国网络安全机构 CISA 和 FBI 周四发布了安全设计警报，警告路径遍历软件漏洞被利用来针对关键基础设施实体进行攻击。**  
  
路径遍历缺陷也称为目录遍历，它依赖于受操纵的用户输入来访问不应访问的应用程序文件和目录。成功利用该漏洞允许威胁行为者操纵任意文件、读取敏感数据，并可能完全破坏系统。  
  
路径遍历缺陷已被记录了二十多年，并在 2007 年被认为是“不可原谅的”，它仍然是软件中的一类持续存在的错误，最近至少有两个问题被利用针对关键基础设施部门，包括医疗保健和公共卫生组织。  
<table><tbody><tr><td width="558" valign="top" style="word-break: break-all;"><p style="margin-block: 0.25em 0.5em;color: rgb(0, 0, 0);font-family: roboto, sans-serif;font-size: 18px;letter-spacing: normal;text-align: start;text-wrap: wrap;"><span style="vertical-align: inherit;">路径遍历攻击（也称为目录遍历）旨在访问存储在 Web 根文件夹之外的文件和目录。通过操作引用具有“点-点-斜杠（../）”序列及其变体的文件的变量或使用绝对文件路径，可以访问存储在文件系统上的任意文件和目录，包括应用程序源代码或配置和关键系统文件。应该注意的是，对文件的访问受到系统操作访问控制的限制（例如在 Microsoft Windows 操作系统上锁定或正在使用的文件的情况）。</span></p><p style="margin-block: 0.25em 0.5em;color: rgb(0, 0, 0);font-family: roboto, sans-serif;font-size: 18px;letter-spacing: normal;text-align: start;text-wrap: wrap;"><span style="vertical-align: inherit;">这种攻击也称为“点-点-斜杠”、“目录遍历”、“目录攀爬”和“回溯”。</span></p><h2 style="margin-top: 2px;margin-bottom: 8px;font-family: roboto, sans-serif;font-weight: bold;margin-block: 0.45em 0.15em;color: rgb(0, 0, 0);letter-spacing: normal;text-align: start;text-wrap: wrap;"><span style="vertical-align: inherit;">相关安全活动</span></h2><h3 style="margin-top: 2px;margin-bottom: 8px;font-family: roboto, sans-serif;font-weight: bold;margin-block: 0.45em 0.15em;color: rgb(0, 0, 0);letter-spacing: normal;text-align: start;text-wrap: wrap;"><span style="vertical-align: inherit;">如何避免路径遍历漏洞</span></h3><p style="margin-block: 0.25em 0.5em;color: rgb(0, 0, 0);font-family: roboto, sans-serif;font-size: 18px;letter-spacing: normal;text-align: start;text-wrap: wrap;"><span style="vertical-align: inherit;">除了最简单的 Web 应用程序之外，所有应用程序都必须包含本地资源，例如图像、主题、其他脚本等。每次应用程序包含资源或文件时，攻击者都可能存在包含您未授权的文件或远程资源的风险。</span></p><h4 style="margin-top: 2px;margin-bottom: 8px;font-family: roboto, sans-serif;font-weight: bold;margin-block: 0.45em 0.15em;color: rgb(0, 0, 0);font-size: 18px;letter-spacing: normal;text-align: start;text-wrap: wrap;"><span style="vertical-align: inherit;">如何识别您是否容易受到伤害</span></h4><ul style="color: rgb(0, 0, 0);font-family: roboto, sans-serif;font-size: 18px;letter-spacing: normal;text-align: start;text-wrap: wrap;" class="list-paddingleft-1"><li><p><span style="vertical-align: inherit;">确保您了解底层操作系统将如何处理传递给它的文件名。</span></p></li><li><p><span style="vertical-align: inherit;">不要将敏感配置文件存储在 Web 根目录中</span></p></li><li><p><span style="vertical-align: inherit;">对于 Windows IIS 服务器，Web 根目录不应位于系统磁盘上，以防止递归遍历回系统目录。</span></p></li></ul><h4 style="margin-top: 2px;margin-bottom: 8px;font-family: roboto, sans-serif;font-weight: bold;margin-block: 0.45em 0.15em;color: rgb(0, 0, 0);font-size: 18px;letter-spacing: normal;text-align: start;text-wrap: wrap;"><span style="vertical-align: inherit;">如何保护自己</span></h4><ul style="color: rgb(0, 0, 0);font-family: roboto, sans-serif;font-size: 18px;letter-spacing: normal;text-align: start;text-wrap: wrap;" class="list-paddingleft-1"><li><p><span style="vertical-align: inherit;">使用文件系统调用时更喜欢在没有用户输入的情况下工作</span></p></li><li><p><span style="vertical-align: inherit;">在模板化或使用语言文件时使用索引而不是文件名的实际部分（即用户提交的值 5 = 捷克斯洛伐克语，而不是期望用户返回“捷克斯洛伐克语”）</span></p></li><li><p><span style="vertical-align: inherit;">确保用户无法提供路径的所有部分 - 用您的路径代码将其包围</span></p></li><li><p><span style="vertical-align: inherit;">仅接受已知的信息来验证用户的输入 - 不要清理数据</span></p></li><li><p><span style="vertical-align: inherit;">使用 chroot 监狱和代码访问策略来限制文件的获取或保存位置</span></p></li><li><p><span style="vertical-align: inherit;">如果强制使用用户输入进行文件操作，请在使用文件 io API 之前对输入进行规范化，例如</span><span style="vertical-align: inherit;">normalize()</span><span style="vertical-align: inherit;">。</span></p></li></ul></td></tr></tbody></table>  
  
针对影响 ConnectWise ScreenConnect (   
CVE-2024-1708  
 ) 和 Cisco AppDynamics Controller (   
CVE-2024-20345  
 ) 的两个漏洞的利用，CISA 和 FBI  
敦促各组织  
(PDF) 确保其软件开发人员消除此漏洞安全缺陷类别。  
  
CISA 目前在其已知利用漏洞 (KEV) 目录中列出了 55 个路径遍历缺陷。  
  
这两个美国政府机构强调，设计安全的软件开发生命周期是消除安全漏洞（包括路径遍历缺陷）的基础，因为产品的构建方式可以合理地保护它们免受错误利用。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rTibWNx9ARWno9yhGfI5cJGI0brpy6yCiczo6mv189oMlythYG8o4UDSqzk8FGmBiay0Ip0631rOY3R8I97ricIb8Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
CISA 和 FBI 指出：“从设计阶段开始，一直到产品发布和更新，从一开始就纳入这种风险缓解措施，既可以减轻客户的网络安全负担，也可以减轻公众的风险。”  
  
众所周知且有效的缓解措施包括对文件使用随机标识符并单独存储元数据，或者限制文件名中的字符数并确保上传的文件没有执行权限。  
  
OWASP  
关于路径遍历缺陷的指南包括建议软件制造商和云服务运营商审查和实施的其他缓解措施。  
  
此外，建议组织测试产品是否存在路径遍历错误，并遵守  
2023 年 10 月发布的   
安全设计指南中详细介绍的三项原则，保护自己免受此类漏洞的利用。  
  
两家机构表示，通过全面实施推荐的安全设计原则和实践，软件制造商可以保护其客户免受各种恶意攻击。  
  
CISA 和 FBI 指出：“此外，CISA 和 FBI 敦促制造商发布自己的安全设计路线图，以证明他们不仅仅是实施战术控制，而是从战略上重新考虑他们在保护客户安全方面的责任。”  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWhJou9CCpqmibD6ldgHL2ONAnycCV5yOcv7NiccibzQb5oMWLVmYhwK6jQaSapdQNKVoTAePYIKqmmicA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**精彩回顾：祺印说信安2024之前**  
  
[230个网络和数据安全相关法律法规规范文件打包下载](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105479&idx=2&sn=1f51edc838bc6dbe991b184178d6d0ac&chksm=8bbcc13ebccb4828eb26b14990d39068d4d1e7c3f43989dd0ade728567228036ef8f12f55208&scene=21#wechat_redirect)  
  
  
[2023年收集标准合集下载](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104571&idx=1&sn=b2b0a1465e8d4856f593fa7a3b7fcd6c&chksm=8bbccd42bccb44540a72239af3de30db90adafde6d5c4217aa1b15600ba47feb550f5fa659bd&scene=21#wechat_redirect)  
  
  
[收集信通院白皮书系列合集（618个）下载](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104887&idx=1&sn=dde6bdba86b2b89bb59011ce58baf7cc&chksm=8bbcc28ebccb4b98219438b9dbf546bbfc1dce48f461858213104eb2790c1f92b54bc1400073&scene=21#wechat_redirect)  
  
  
[美国网络安全机构更新了DDoS缓解指南](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105801&idx=1&sn=b340e713b599e7e699c9dd938b0fc0f9&chksm=8bbcc670bccb4f66583f4a2ba39a5089fa5762e5239e9ee0050aac25ba761c5b04249e3d7531&scene=21#wechat_redirect)  
  
  
[CISA发布桌面演习包：水坝部门-水电设施](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105828&idx=2&sn=7b0752fd24c250c55093891a966b7e71&chksm=8bbcc65dbccb4f4b620557079fdf2473b65a1aa91aa553698b19e887522229d3600724526f6e&scene=21#wechat_redirect)  
  
  
**>>>网络安全等级保护<<<**  
  
[网络安全等级保护：等级保护工作、分级保护工作、密码管理工作三者之间的关系](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652098579&idx=1&sn=56da5aedb263c64196a74c5f148af682&chksm=8bbcfa2abccb733ca8dd898d7c0b06d98244ca76bd7be343482369fa80546554cced706fa74c&scene=21#wechat_redirect)  
  
  
[等级保护网络架构安全要求与网络分段的7个安全优点](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103736&idx=1&sn=9862de51a047cfde70c4575815ecb5c5&chksm=8bbcce01bccb4717a7bb7941cfd80fb25e9d0da8139c184e4ad245bf53fc91b1d6944bc85916&scene=21#wechat_redirect)  
  
  
[网络安全等级保护相关知识汇总](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652102246&idx=1&sn=6da86a0ad9a923edca47618aedac0ac9&chksm=8bbcf45fbccb7d49635a50913000dde2fc38b1beadf4172d7877b8093c721f727c1819cf1e0f&scene=21#wechat_redirect)  
  
  
[等级保护测评之安全物理环境测评PPT](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105585&idx=1&sn=1e0e42b3c32fe29643849c82db415a28&chksm=8bbcc148bccb485e1b89a4fc08efcfd501ec0c25417acf29a6ce8dd1ed96d6a88a59cf2cfb7d&scene=21#wechat_redirect)  
  
  
**>>>数据安全系列<<<**  
  
[数据安全管理从哪里开始](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103384&idx=1&sn=391073e6109ff105f02be9029e01c697&chksm=8bbcc8e1bccb41f7fe478a3d22757d61f10dcf42548c1c02c0579b8f161277e527ba98ccb542&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据安全策略规划](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104021&idx=1&sn=7f80bb27ce6ad7c9debe83c172ff9f73&chksm=8bbccf6cbccb467a0971b9de4a8b14851c2666ad6934a88b8324a1ffc4b5cf5109cbc3976697&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据库安全重要性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104183&idx=2&sn=f2a98256b0497ce3a99c0ad30223bf40&chksm=8bbccfcebccb46d8aac9f8a5c8d1f46061ca61ad69b3a61d52d3dc614e1e18ae65d982a5574b&scene=21#wechat_redirect)  
  
  
[数据安全知识：数据整理与数据清理](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105810&idx=2&sn=97ff4a8d1f2c7f3f6a0252f4df58b20b&chksm=8bbcc66bbccb4f7d058c46bc9c67d34c2042993f2ad32c7732d9816f8dfa4abb7e10f0fd307f&scene=21#wechat_redirect)  
  
  
******>>>错与罚<<<**  
  
[北京多家公司因不履行网络安全保护义务被处罚！“两高一弱”仍然是安全隐患重点](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104010&idx=1&sn=0ddfdc41a52d235c99269b784b7858fa&chksm=8bbccf73bccb4665d0c29f8067b90e0e9b48894d2d4bbb9da98e64218efa47e36c32034a4775&scene=21#wechat_redirect)  
  
****  
  
[严厉打击网络谣言！商丘警方公布4起典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104388&idx=1&sn=9da4f7c6e055ff4e5bae9c0b10420538&chksm=8bbcccfdbccb45eb58a4322c3845b7ea5c743fe746a09e103f88aaaac84a2e997ab3b4658fa2&scene=21#wechat_redirect)  
  
  
[新乡网安依法查处3起不履行网络安全保护义务案](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105454&idx=1&sn=12d568c4c5b717b549b43da1833d3ac3&chksm=8bbcc0d7bccb49c199277862be7a2f6bd6f3699a720c5ac919371f34f31acd0efd56397d9212&scene=21#wechat_redirect)  
  
  
[侮辱南阳火灾遇难学生的“谯城芳芳姐”获十日行政拘留](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104388&idx=2&sn=4824c66acd50a0701a117d12408ddf80&chksm=8bbcccfdbccb45ebfe3a03f67e98ddc5239ed0490efa326da41dc6abcdef432c12a6124eef12&scene=21#wechat_redirect)  
  
  
[宁夏网警公布5起打击谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104388&idx=3&sn=3ab286ac8ead9305cbc8db6fcd1d25a6&chksm=8bbcccfdbccb45ebe9a7431baddbcf8aaf4f3e77545b0bcac0da033e84aed8fb7c9b76efb691&scene=21#wechat_redirect)  
  
  
[吉林警方公布3起、湖北公安公布5起打击谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104256&idx=3&sn=1cec040494e2fe846ae1f4d19e9de390&chksm=8bbccc79bccb456f95523f31460e34fd5627344f26adb4fed2358b2d5a0178c5ef9fbb4d1439&scene=21#wechat_redirect)  
  
  
[安徽警方依法打击整治网络谣言10起典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104242&idx=3&sn=90a9f1e57b9e0ad43206eea3da80842c&chksm=8bbccc0bbccb451da48561fc6b3e6bee505be0f5a3e67ec5ac01bfa0dae2fd0d9a8bc23515a2&scene=21#wechat_redirect)  
  
  
[2023年度国家网络与信息安全信息通报工作总结会议在京召开](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104222&idx=2&sn=949bca98b6427c7d443ded04c6779a4d&chksm=8bbccc27bccb45313a34056bc7480bc14c0dc502250491a8a566f6b651f604b3f5b1b5753108&scene=21#wechat_redirect)  
  
  
[焦点访谈丨拒绝“按键”伤人 避免网络戾气变成伤人利器](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=6&sn=554d342874f552e8107d81ac664ae2e5&chksm=8bbccc2fbccb45392b7d1bb952aae7ac6a2fe4d1fdfa05512660a35645318afe0fc36f4414a4&scene=21#wechat_redirect)  
  
  
[全国公安厅局长会议召开 忠实履行神圣职责 为扎实稳健推进中国式现代化贡献公安力量](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=2&sn=125e830221fe7b1f3522bbf0205814fd&chksm=8bbccc2fbccb45398c2cc7393a957d5609feff89aae0f14b2e1c895a52642fe3940c9f145a89&scene=21#wechat_redirect)  
  
  
[公安部：纵深推进全面从严管党治警 着力锻造忠诚干净担当的新时代公安铁军](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=3&sn=878a4f16e8c21e2bf7903cba054e135f&chksm=8bbccc2fbccb4539551b2f6c98a75f3b6dfddc9cc7322a23123d6a71450efc0a8bde58d2c5eb&scene=21#wechat_redirect)  
  
  
[山西公布10、辽宁网警公布6起打击谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=4&sn=4a425e447b3f74e37a3e029ea26fb2c7&chksm=8bbccc2fbccb4539286ea4900236dd52dee37cbc74347ab5e9147426a2e73c5df808f428ad8c&scene=21#wechat_redirect)  
  
  
[重庆璧山出现比缅甸还恐怖的新型背债人？警方：系某房产中介为博眼球造谣](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104214&idx=5&sn=d743fe9c40fb4217584fb2ba5561c0df&chksm=8bbccc2fbccb4539c25341414c8ad6b4c6eb3aefc6b0e3b7a69c2f2b647ba46567af3d53ed46&scene=21#wechat_redirect)  
  
  
[上海、四川、浙江、福建警方宣传和打击整治网络谣言](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104159&idx=3&sn=cf504c3cfe1a938ce188f1f1d2e84921&chksm=8bbccfe6bccb46f01e547155be9b9b2af86c54c95659c9be99e1e247c4e60cbbc354946d27b2&scene=21#wechat_redirect)  
  
  
[四川德阳网警开展打击整治网络谣言宣传活动](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104077&idx=3&sn=66b3ec60984cdf4ea12f5a65cd7dfc9d&chksm=8bbccfb4bccb46a24b07a39022d717e962a18b389c135392dba1813f91dccee84bc8d12610a9&scene=21#wechat_redirect)  
  
  
[广安警方公布4起打击整治网络谣言典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104077&idx=4&sn=ba2c2112d68839753ef1a4880f3db435&chksm=8bbccfb4bccb46a22f39036676fe59cbdb5c1013ac120d6ce40a71130859ffc031a8b5084f07&scene=21#wechat_redirect)  
  
  
[四川查处两起利用AI编造、传播网络谣言案件](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104077&idx=5&sn=a5b11dc662e274df84fc7ccfd920877e&chksm=8bbccfb4bccb46a2e0daa6ff57acdf6ef282285bc2fdaba7cf2adcfa49d22765dfae1cdfe59f&scene=21#wechat_redirect)  
  
  
[西安网警依法处置一起网络暴力案件](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104021&idx=3&sn=0115bec6c696677cbfbfd227563417d4&chksm=8bbccf6cbccb467abebd9562fdbe58ff13f73130b95e6b4049c19ece0113d7b08e50c5359820&scene=21#wechat_redirect)  
  
  
[中信银行被罚400万，涉信息安全风险隐患未得到整改、虚假演练等](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103991&idx=1&sn=0cab9d0e32c9f69cab628b843bf73d4e&chksm=8bbccf0ebccb46187f7efe2016109ced6bdaef4ff8f6fd9d90790e36e3e623fe4483398992e0&scene=21#wechat_redirect)  
  
  
[中行被罚430万，涉迟报重要信息系统重大突发事件等](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103970&idx=2&sn=76254b9a3981e3fa57e4957aaaeb16c6&chksm=8bbccf1bbccb460d7d23b6b7b165005d22a33c21443632cbcca4e162d6aeaa06d9025783f638&scene=21#wechat_redirect)  
  
  
[新疆警方公布5起打击整治网络谣言典型案件](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103970&idx=4&sn=76410ed268999f04052b88352fa2be7e&chksm=8bbccf1bbccb460de37e1ef991c384e7e793b4f26fc97e419bcf13a0fae86b1ea874e57be351&scene=21#wechat_redirect)  
  
  
[山西忻州一网民因编造地震谣言被依法查处](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103970&idx=3&sn=de03afd0974ff1740044c29da6016604&chksm=8bbccf1bbccb460d5b5b70f919342b50efb5bb9ba9700f7fe606cfc6c74c827dcc2402e17e9d&scene=21#wechat_redirect)  
  
  
[公安部召开新闻发布会通报打击黑客类违法犯罪举措成效并答记者问](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103951&idx=2&sn=d4b7d5aebc16a942fb695bca3d414f4e&chksm=8bbccf36bccb46204f3274379ffd3c8903c4acb2469447c5b6515f7172e6b1a187e790c0ed42&scene=21#wechat_redirect)  
  
  
[有坏人！快藏好您的个人信息](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103951&idx=3&sn=a79b0b73813585d91ac550bd47b4455f&chksm=8bbccf36bccb462041e356e29f05d20c12736039871290414a0369a8ade194f635e8eeafa3ca&scene=21#wechat_redirect)  
  
  
[在西藏架设“GOIP”设备给骗子提供帮助，10人落网！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103951&idx=4&sn=5a29a6513ef65004fa9a52cc48a649ac&chksm=8bbccf36bccb4620e2c4151522f80dce5c8305587e9da66eebdfb26938a174c9d53b7a4469ed&scene=21#wechat_redirect)  
  
  
[网上买卖传播淫秽物品，触犯法律！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103940&idx=4&sn=b52f4c08d55e271ef299a174ab357f49&chksm=8bbccf3dbccb462b21ed00751ed278683c0927e2c2974adce3d24fff7a8771519f5480417e03&scene=21#wechat_redirect)  
  
  
[“温州帮”竟然是缅北电诈后台？警方通报来了](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103940&idx=5&sn=22173da928f67880a4a37a586dc7683c&chksm=8bbccf3dbccb462b5717c1fe4350d89b671183cba8d5278c294e063f1856fec41a0b9ace54f3&scene=21#wechat_redirect)  
  
  
[借甘肃积石山地震造谣博流量，行拘！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=3&sn=11ff4bcc6cc789554db01ea422185861&chksm=8bbccecdbccb47dbb07650da1243c57eb754e90ca8cff97384af1a691ef6a10f198634b93654&scene=21#wechat_redirect)  
  
  
[陕西警方公布6起打谣典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=4&sn=9ade7706756da02f2445d7bacc97d5ca&chksm=8bbccecdbccb47dba6b27b9b7d5f2f650dac3419e2fa55bdd47be8d81041f39a1af416fd5815&scene=21#wechat_redirect)  
  
  
[“再来一次12级地震”，行拘！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=5&sn=1bc2675b734a42942654184e8763b10e&chksm=8bbccecdbccb47db54e8cc53eb43b9401a318f5c11060aa0c807eb53ce27590e668ee94e32ab&scene=21#wechat_redirect)  
  
  
[江西警方公布7起“打谣”典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=6&sn=20e55dcdc18a802bf2079e3706050546&chksm=8bbccecdbccb47dbeea304bcbf81f23fb6c8ac7eb970893321f0b825277e5e1998e099cd9d47&scene=21#wechat_redirect)  
  
  
[江苏警方公布8起打谣典型案例](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=7&sn=b4692b982f6ad99a087ccb5f1d5f3a04&chksm=8bbccecdbccb47dbb96efae0b284dd655ef7e526ce811ad0ff6c2a92e04e0e1eac94110f4aa3&scene=21#wechat_redirect)  
  
  
[越想越生气，酒后干出糊涂事……](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103924&idx=8&sn=5e96bbf3eb7076304c0193e1b21bdb81&chksm=8bbccecdbccb47dbd4ec4e1a6539eb19791b6e2120e4dbcf7cf91f49b94e601eec1897517029&scene=21#wechat_redirect)  
  
  
[邯郸刘某某因编造网络谣言被依法查处！](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103925&idx=3&sn=a602191fd3828335576572dd1455d167&chksm=8bbcceccbccb47da5fac006e6d897247911225b784ec1de5b7c34a6ca7ba31944c243d9137eb&scene=21#wechat_redirect)  
  
  
**>>>其他<<<**  
  
[2023年10佳免费网络威胁情报来源和工具](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103402&idx=1&sn=80a1ee98453d96a6f2304272d2a6b33e&chksm=8bbcc8d3bccb41c5fe204b9933fbded47cd14612e3101111b2f806d8a136a61ff27577dfd765&scene=21#wechat_redirect)  
  
  
[2023年网络安全资金下降40%](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104036&idx=3&sn=797c6ac97c1c280791cbcf44737eae0c&chksm=8bbccf5dbccb464bc612673aa47f43a0affceaaa6827381f54333baf7da6994882bcff4cdbd9&scene=21#wechat_redirect)  
  
  
[为什么攻击模拟是避免 KO 的关键](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104101&idx=1&sn=4f52a7b75387d67862021b8f0d647d26&chksm=8bbccf9cbccb468ad8e85019c4978ff5f374845082160f75b52d9fd226b635e3f4815fb1edf9&scene=21#wechat_redirect)  
  
  
[持续安全监控对于稳健的网络安全策略的重要性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103729&idx=3&sn=688da0c1e70c3975b24d7036e6f90c3d&chksm=8bbcce08bccb471e89426f5a0089aa335689403215ab6b4d0cea9fa159c2d2c7bfac94fd59f2&scene=21#wechat_redirect)  
  
  
[网络安全策略：远程访问策略](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104095&idx=2&sn=e8b2c6e7b9ec9c7a5e2da7f0df549ce8&chksm=8bbccfa6bccb46b0f847137b32cc0426dd05cf8a4b6d8b1ceeaee8e57482c70873a42041f771&scene=21#wechat_redirect)  
  
  
[网络安全策略：账户管理策略](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104021&idx=2&sn=c796ce34bf877501045259cda0097256&chksm=8bbccf6cbccb467ac55aa14b1a35004cb8f40dbab7a8760cb5ad2f06d15b3a15c85e38011087&scene=21#wechat_redirect)  
  
  
[保护企业的19项网络安全最佳实践](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104183&idx=1&sn=8f8693bdb34a0bba9975cade5b43b13d&chksm=8bbccfcebccb46d8e12d90e65018f0ee875ae2915ca5fc2e23eb86747361ddffcfec27561933&scene=21#wechat_redirect)  
  
  
[实现混合网络时代的“无摩擦防御”](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104222&idx=1&sn=f15fd89240d1c5cb8bb83ccefaf9349a&chksm=8bbccc27bccb453100a3c15379d8e0f666c061c93ff25913e91de947a9d119f47b8d53045f25&scene=21#wechat_redirect)  
  
  
[物联网不是一份持续接受的礼物](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104222&idx=3&sn=ba74d7b9bb872a4da2572cb5ebbdad0f&chksm=8bbccc27bccb453114fc7ce6e43699a17a777a9f398981098df51574501c636efed381125342&scene=21#wechat_redirect)  
  
  
[确保完整的 IT 资产可见性及安全](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652104844&idx=1&sn=bd54fd2cf9eb3eae1f084b751d4760bc&chksm=8bbcc2b5bccb4ba34125c429f2df73860919bc90cbabfe00a166c9dd90f1b82d19b3dd801f9a&scene=21#wechat_redirect)  
  
  
[网络安全行业裁员的负面影响专业人员可能涌入网络犯罪](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105605&idx=1&sn=59949759982b98e16df4aed01277a75d&chksm=8bbcc1bcbccb48aaf08678b7126dd3749a2d8d0738de05e134a48092e15b301dfd0f9d434a1e&scene=21#wechat_redirect)  
  
  
[现代网络安全基于风险的漏洞管理](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105581&idx=1&sn=3ee3917aefd05af54831bd9d20b7a263&chksm=8bbcc154bccb4842a4f6f003ea864973ed9de7e5d538cb90e3cbcc296790457f4afee0bc6517&scene=21#wechat_redirect)  
  
  
[网络安全框架2.0版之CSF层的概念图示](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105463&idx=1&sn=41549e17df8747ed1e344a0233b7c38c&chksm=8bbcc0cebccb49d8122582023549e6f8a5f2b8f2895e3519780d147b9aa6575c34a5b6a41221&scene=21#wechat_redirect)  
  
  
[网络安全领域薪酬新趋势](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105630&idx=1&sn=f657d963b57ec5550446eac034b7af3c&chksm=8bbcc1a7bccb48b180caaffa287a57c3c10189e285f3ddc75fb6a09dca6c98fbc3c733a6e4ea&scene=21#wechat_redirect)  
  
  
[英国政府发布云 SCADA 安全指南](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105700&idx=2&sn=85232102c8e2ccb1aef6d4b25778b19d&chksm=8bbcc1ddbccb48cb42d5dfb0fc3e7467d73d5c1b6c8e54be8538cb80793f22e3454bdec4fcd5&scene=21#wechat_redirect)  
  
  
[网络安全框架2.0版之CSF核心](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105683&idx=1&sn=105cbc4e57734a99921f0a7953c8faf4&chksm=8bbcc1eabccb48fc056ed771882e12f86f8d681e407229245308a1f23f4f9bcaf70b1152666a&scene=21#wechat_redirect)  
  
  
[网络安全框架2.0版之前言和概述](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105817&idx=1&sn=84e5cdb5911e5a2877856e0c27f9cf70&chksm=8bbcc660bccb4f76fab5eed4e838b8607fc68cb22e5d3fd0691c9c13ad00c68cf8be0556505b&scene=21#wechat_redirect)  
  
  
[网络安全框架2.0版之CSF核心简介](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105833&idx=1&sn=fa231bcb6df284b208ad285e2dd0bf38&chksm=8bbcc650bccb4f46d897b902083a5ddabbcf8f40ae018e015b67c2c904e312ddef9e558a1943&scene=21#wechat_redirect)  
  
  
[安全运营和事件管理的10个教训](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105682&idx=1&sn=f1b1dc3213e411f6715081358f7b8f23&chksm=8bbcc1ebbccb48fd11f476a88ba5a5643df8300baa7827ac611680acb66a14a9b72649997ff9&scene=21#wechat_redirect)  
  
  
[看老外如何为网络安全合规时代做好准备](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105810&idx=1&sn=97f4b3f8139765311f71de4155a56773&chksm=8bbcc66bbccb4f7d49d7fdf4aa5f81917b8264f3326246c9e9f90bdb8cfc7f8b60a8449de074&scene=21#wechat_redirect)  
  
  
[基于打字模式的键盘声学侧通道攻击](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105801&idx=3&sn=56da9e15ae8d18b2a7c58836404e258b&chksm=8bbcc670bccb4f66e4818b20967ac2a69117e7664ca3f0b4487cd881231cfc2443d2b859d9ef&scene=21#wechat_redirect)  
  
  
[运营技术 (OT) 和网络安全：保护关键信息基础设施](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105681&idx=1&sn=120497f0a08692e81c096e93c0e156e0&chksm=8bbcc1e8bccb48fe65417f55d1bdea9825893cf19b4d1b16c9a322a5045a64967c708397bbfc&scene=21#wechat_redirect)  
  
  
[运营技术之云托管的监控和数据采集 (SCADA)](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105828&idx=1&sn=3fcd3d657b6f1a4ee713ef5b201caee9&chksm=8bbcc65dbccb4f4ba53f303e36a09bb5183826bd13a12186493c5333653ad3391f3694f02970&scene=21#wechat_redirect)  
  
  
[运营技术之技术和云解决方案适用性](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652105817&idx=2&sn=fcef609527baba249e9c783731e4fd2f&chksm=8bbcc660bccb4f76b27d2af2c372ece3958b762e68d6e23fa99f8d08d9a0ae0cdda05c05d4a1&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652103528&idx=1&sn=fef657b5a0e1982eff81b5c92f33db57&chksm=8bbcc951bccb4047211ef41c22541966c1c25dbee9f79c45e1e429fb485f675b706babdcf347&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzU5MzQzMA==&mid=2652100366&idx=1&sn=27d04d1abc7a02a6b731322416805a1a&chksm=8bbcfd37bccb7421ab6f679bd83b34e02c930e2beca304844ee59a8843d5b18df1bf52d4e032&scene=21#wechat_redirect)  
  
