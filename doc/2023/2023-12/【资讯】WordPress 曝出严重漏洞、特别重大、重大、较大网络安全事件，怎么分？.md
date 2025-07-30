#  【资讯】WordPress 曝出严重漏洞、特别重大、重大、较大网络安全事件，怎么分？   
KaitouLee整理  黑客白帽子   2023-12-10 09:02  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404&random=0.21447236831996852&random=0.8815771345375145 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834&random=0.5456659019781378&random=0.7540796948001678 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png&random=0.9645460004599724&random=0.6990385736871094 "")  
  
   
  
1  
  
现已修复！WordPress 曝出严重漏洞  

				  
  
   
  
  
Bleeping Computer 网站消息，WordPress 近期发布了6.4.2更新版本，修复了一个远程代码执行 (RCE) 漏洞。据悉，该漏洞能够与另外一个安全漏洞形成“联动”，允许威胁攻击者在目标网站上运行任意 PHP 代码。  
  
WordPress 是一种非常流行的开源内容管理系统（CMS），主要用于创建和管理网站，目前已经有8 亿多个网站使用它，约占互联网上所有网站的45%。然而，该项目的安全团队在 WordPress core 6.4中发现了一个面向属性编程（POP）链漏洞，在某些条件下，该漏洞可允许未经授权的威胁攻击者执行任意 PHP 代码。  
  
POP 链“要求”威胁攻击者控制反序列化对象的所有属性，而 PHP 的 unserialize()函数正好可以做到这一点，一旦这样操作的话，威胁攻击者有可能通过控制发送到 megic 方法（如”_wakeup()”）的值来劫持应用程序的流程。值得一提的是，这个安全问题需要受害目标网站上存在 PHP 对象注入漏洞（可能存在于插件或主题附加组件中）才能产生最恶劣的影响。  
  
WordPress 方面指出，该远程代码执行漏洞虽然在内核中无法直接被攻击者利用，但安全团队认为如果与某些插件结合使用，尤其是在多站点安装中，就有可能造成严重后果。  
  
Wordfence 的 WordPress 安全专家的 PSA 提供了有关该安全问题的一些技术细节，并解释称该安全问题出现在 WordPress 6.4中引入的”WP_HTML_Token”类中，以改进块编辑器中的 HTML 解析，该类包含一个”__destruct”magic 方法，该方法使用”call_user_func”执行在”on_decurt”属性中定义的函数，并将”bookmark_name”作为参数。  
  
最后，研究人员强调，威胁攻击者能够利用对象注入漏洞，轻松控制这些属性来执行任意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0yaCkmvV07e9nHSWxu0LZNSNA1uSHJVPZJauWvMk6BqVicCTQVpabKDoZ1YbCfIZx4EAAOVPOFb87Q/640?wx_fmt=png&from=appmsg&random=0.09883122335577688&random=0.8054336001217761 "")  
  
有条件执行回调函数的类析构函数（Patchstack）  
  
尽管该安全漏洞本身可能并不严重，但由于需要在已安装和活动的插件或主题上注入对象，WordPress 核心中存在可利用的 POP 链会显著增加 WordPress 网站的总体风险。Patchstack 针对 WordPress 和插件的安全平台发出的通知中强调，针对该问题的漏洞利用链已于几周前上传至 GitHub，随后被添加到用于 PHP 应用程序安全测试的 PHPGGC 库中。  
  
最后，即使该漏洞只是潜在的安全问题，而且在某些特定情况下才可以被威胁攻击者利用，但安全研究人员还是建议管理员尽快更新到最新的 WordPress 版本。  
  
   
```

转自FreeBuf.COM，原文链接：https://www.freebuf.com/news/386057.html
```  
  
****  
   
  
2  
  
网络安全事件分级指南  

				  
  
   
  
**12月8日，国家网信办发布了《网络安全事件报告管理办法（征求意见稿）》，面向社会公开征求意见。其中，附件里对网络安全事件分级作出了规定，具体如下：**  
  
  
**网络安全事件分级指南**  
  
**一、特别重大网络安全事件**  
  
符合下列情形之一的，为特别重大网络安全事件：  
  
1.重要网络和信息系统遭受特别严重的系统损失，造成系统大面积瘫痪，丧失业务处理能力。  
  
2.国家秘密信息、重要敏感信息、重要数据丢失或被窃取、篡改、假冒，对国家安全和社会稳定构成特别严重威胁。  
  
3.其他对国家安全、社会秩序、经济建设和公众利益构成特别严重威胁、造成特别严重影响的网络安全事件。  
  
通常情况下，满足下列条件之一的，可判别为特别重大网络安全事件：  
  
1.省级以上党政机关门户网站、重点新闻网站因攻击、故障，导致24小时以上不能访问。  
  
2.关键信息基础设施整体中断运行6小时以上或主要功能中断运行24小时以上。  
  
3.影响单个省级行政区30%以上人口的工作、生活。  
  
4.影响1000万人以上用水、用电、用气、用油、取暖或交通出行。  
  
5.重要数据泄露或被窃取，对国家安全和社会稳定构成特别严重威胁。  
  
6.泄露1亿人以上个人信息。  
  
7.党政机关门户网站、重点新闻网站、网络平台等重要信息系统被攻击篡改，导致违法有害信息特大范围传播。以下情况之一，可认定为“特大范围”：  
  
（1）在主页上出现并持续6小时以上，或在其他页面出现并持续24小时以上；  
  
（2）通过社交平台转发10万次以上；  
  
（3）浏览或点击次数100万以上；  
  
（4）省级以上网信部门、公安部门认定为是“特大范围传播”的。  
  
8.造成1亿元以上的直接经济损失。  
  
9.其他对国家安全、社会秩序、经济建设和公众利益构成特别严重威胁、造成特别严重影响的网络安全事件。  
  
**二、重大网络安全事件**  
  
符合下列情形之一且未达到特别重大网络安全事件的，为重大网络安全事件：  
  
1.重要网络和信息系统遭受严重的系统损失，造成系统长时间中断或局部瘫痪，业务处理能力受到极大影响。  
  
2.国家秘密信息、重要敏感信息、重要数据丢失或被窃取、篡改、假冒，对国家安全和社会稳定构成严重威胁。  
  
3.其他对国家安全、社会秩序、经济建设和公众利益构成严重威胁、造成严重影响的网络安全事件。  
  
通常情况下，满足下列条件之一的，可判别为重大网络安全事件：  
  
1.地市级以上党政机关门户网站、重点新闻网站因攻击、故障，导致6小时以上不能访问。  
  
2.关键信息基础设施整体中断运行2小时以上或主要功能中断运行6小时以上。  
  
3.影响单个地市级行政区30%以上人口的工作、生活。  
  
4.影响100万人以上用水、用电、用气、用油、取暖或交通出行。  
  
5.重要数据泄露或被窃取，对国家安全和社会稳定构成严重威胁。  
  
6.泄露1000万人以上个人信息。  
  
7.党政机关门户网站、重点新闻网站、网络平台等被攻击篡改，导致违法有害信息大范围传播。以下情况之一，可认定为“大范围”：  
  
（1）在主页上出现并持续2小时以上，或在其他页面出现并持续12小时以上；  
  
（2）通过社交平台转发1万次以上；  
  
（3）浏览或点击次数10万以上；  
  
（4）省级以上网信部门、公安部门认定为是“大范围传播”的。  
  
8.造成2000万元以上的直接经济损失。  
  
9.其他对国家安全、社会秩序、经济建设和公众利益构成严重威胁、造成严重影响的网络安全事件。  
  
**三、较大网络安全事件**  
  
符合下列情形之一且未达到重大网络安全事件的，为较大网络安全事件：  
  
1.重要网络和信息系统遭受较大的系统损失，造成系统中断，明显影响系统效率，业务处理能力受到影响。  
  
2.国家秘密信息、重要敏感信息、重要数据丢失或被窃取、篡改、假冒，对国家安全和社会稳定构成较严重威胁。  
  
3.其他对国家安全、社会秩序、经济建设和公众利益构成较严重威胁、造成较严重影响的网络安全事件。  
  
通常情况下，满足下列条件之一的，可判别为较大网络安全事件：  
  
1.地市级以上党政机关门户网站、重点新闻网站因攻击、故障，导致2小时以上不能访问。  
  
2.关键信息基础设施整体中断运行30分钟以上或主要功能中断运行2小时以上。  
  
3.影响单个地市级行政区10%以上人口的工作、生活。  
  
4.影响10万人以上用水、用电、用气、用油、取暖或交通出行。  
  
5.重要数据泄露或被窃取，对国家安全和社会稳定构成较严重威胁。  
  
6.泄露100万人以上个人信息。  
  
7.党政机关门户网站、重点新闻网站、网络平台等被攻击篡改，导致违法有害信息较大范围传播。以下情况之一，可认定为“较大范围”：  
  
（1）在主页上出现并持续30分钟以上，或在其他页面出现并持续2小时以上；  
  
（2）通过社交平台转发1000次以上；  
  
（3）浏览或点击次数1万以上；  
  
（4）省级以上网信部门、公安部门认定为是“较大范围传播”的。  
  
8.造成500万元以上的直接经济损失。  
  
9.其他对国家安全、社会秩序、经济建设和公众利益构成较严重威胁、造成较严重影响的网络安全事件。  
  
**四、一般网络安全事件**  
  
除上述网络安全事件外，对国家安全、社会秩序、经济建设和公众利益构成一定威胁、造成一定影响的网络安全事件。  
  
注：本指南中的“以上”均包括本数。  
  
来源：中国网信网  
  
  

								  

									  

										  

											  
往期推荐  

										  

									  

									  

								[ 【资讯】俄罗斯军事黑客瞄准北约快速反应部队、因忽视漏洞修复美国联邦服务器受攻击、美国安全局 (CISA) 添加了四个高通漏洞 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936302&idx=1&sn=d49d7c022d70bc50662185c0972bbcff&chksm=8bac5f11bcdbd6077bed978337250363b9435b2c1993f99737bcd15540a938d803cffad628e7&scene=21#wechat_redirect)  

							  
  

								[ 一款更易上手的GUI版xray漏扫工具（附下载） ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936302&idx=2&sn=e1cad443d34676a7e3b5ce469ef86e0f&chksm=8bac5f11bcdbd607c6171a1ed63398c71c2de3fb38ada55c9802e0bec515f4ad7687510137b9&scene=21#wechat_redirect)  

							  
  

								[ 2023年（11月），2500-3000元手机挑选推荐攻略 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936302&idx=3&sn=d4ac4cfc7358a384db33702b7d8d3283&chksm=8bac5f11bcdbd60731b84db52a3a2645eac6a91152ed7ba3cfc46266943ffcb1ba43beb6b51f&scene=21#wechat_redirect)  

							  
  

								[ 【资讯】暗网出售台湾监视名单？3GB 数据售价 10 万美元、研究人员发现新型攻击方式，可通过图像和音频操纵大模型 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936215&idx=1&sn=b4d7339f51622ec37d61a8dc1860d8f6&chksm=8bac5f68bcdbd67e7ad0b850229e59c3019f916af7526c166149a72092c6cbb29b8dba430e85&scene=21#wechat_redirect)  

							  
  

								[ 【渗透测试】渗透测试常用方法总结，大神之笔！ ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936215&idx=2&sn=df847db56abe56618df30876ead08199&chksm=8bac5f68bcdbd67ead17af135d86da0df66f7f944c03366da648824a66ede9f7ea502730b23e&scene=21#wechat_redirect)  

							  
  

								[ 【手机评测推荐】2023年（12月），3500-4000元手机挑选推荐攻略 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936215&idx=3&sn=e1057c4d8666996a1534a321712e7d8e&chksm=8bac5f68bcdbd67ee4b26fc191d7ad13140d8e22baa7d1ac9c6dc9cf37356ee4d7ab99e0ce74&scene=21#wechat_redirect)  

							  
  

								[ 【资讯】安全厂商中标信息、黑客通过虚拟键盘控制iPhone、GitHub的15,000 个 Go 存储库受损 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936137&idx=1&sn=00adcd61d0f534c6216462e807edfd4a&chksm=8bac5fb6bcdbd6a0c703e07fa97a080131c8d87fea0984547681b03eb8a4232f8e7dbf19cca4&scene=21#wechat_redirect)  

							  
  

								[ 【工具分享】一款全自动白帽漏洞扫描器 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936137&idx=2&sn=81a61d8a5bd672f35570e08b2e948dbe&chksm=8bac5fb6bcdbd6a0d6cbd237de0aecb99403a4b5ff28c8f5c5a75c3dcda686a3a41bc7caa9af&scene=21#wechat_redirect)  

							  
  

								[ 【手机评测】2023年（12月），4000-5000元手机挑选攻略 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936137&idx=3&sn=1b5fe35328b47f5d5d4c560de0bf14b4&chksm=8bac5fb6bcdbd6a06474c8b8ca8c5e0446f03d57e0dfc9deca0ae23ffda21b97aa119d32d302&scene=21#wechat_redirect)  

							  
  

								[ 【LSP专享】米娜舞蹈视频10V ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936137&idx=4&sn=aa464a105bd2cf0c03eec455623f1a9b&chksm=8bac5fb6bcdbd6a053e8e8a880b432df9ed72977e8bd6a92a27f6ad60aa6ebe2d2be713f07e0&scene=21#wechat_redirect)  

							  
  

								[ 【资讯】Black Basta 勒索软件团伙出道以来至少“赚取”1.07 亿美元、Zyxel 警告专有 NAS 设备存在严重漏洞 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936032&idx=1&sn=f85e75d7d6409af91b9d4b1e1742c463&chksm=8bac5e1fbcdbd7095b3b8f9751572f1231b20e58b0d94c0d7e4a626cedc94ab98cd0b7055e6a&scene=21#wechat_redirect)  

							  
  

								[ POC管理和漏洞扫描工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936032&idx=2&sn=b1fece65434dd7078c19b45289af5142&chksm=8bac5e1fbcdbd709c7a2cc9f3f505650fc46f56c32a8c54ef840a91a3cd19803f369cf6d45f2&scene=21#wechat_redirect)  

							  
  

								[ 2023年（12月），5000-6000元手机挑选攻略 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936032&idx=3&sn=9a99f21be1aca7883cde26d50cae57fa&chksm=8bac5e1fbcdbd709ede0a6b160dedfea5f61031e05d511b717600687e02baaf0d24495f6d581&scene=21#wechat_redirect)  

							  
  

								[ 【LSP专享】斗鱼女主播米娜舞蹈视频，大摆锤、动感光波、吹笛子什么都有10V ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650936032&idx=4&sn=ecaa5baf7a43f07a77aa92894852e29f&chksm=8bac5e1fbcdbd70973edf34735656b5da8215c9bca468fc90beba0074c19b78333bf01206f8a&scene=21#wechat_redirect)  

							  
  

								[ 【资讯】利用DNF漏洞，两名玩家获利近1亿元 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650935956&idx=1&sn=3551a0c389d5e54a63e4694669a8fef1&chksm=8bac5e6bbcdbd77d4713caca8526cbc8e6171ea16acf1412881ea1d20a4b7962f48ae50cc277&scene=21#wechat_redirect)  

							  
  

								[ 2023年（12月），6000元以上手机挑选攻略 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650935956&idx=2&sn=5e19e86c976683f4f2d338a82d79e3cc&chksm=8bac5e6bbcdbd77d23fd55d7ca0d6b724bc924e28502681b817ee6cc18a7c1631751d33146c5&scene=21#wechat_redirect)  

							  
  

								[ 【LSP专享】哇哦米娜舞蹈视频3V ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650935956&idx=3&sn=bf27b3dbb0e6675f50664ba0d4d4cdb0&chksm=8bac5e6bbcdbd77da7562e4502dad441db675bc528aa6a11ca6ab912b5df1b2c19856c9d3a50&scene=21#wechat_redirect)  

							  
  

								[ CVE-2021-40438 Apache mod_proxy SSRF ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650935891&idx=1&sn=cc2d2e5c033cb7c8388d2a4f2277e187&chksm=8bac5eacbcdbd7ba500c724c27a32d82a72a46c6310103f8d5f33ff63c8bee473f0ffdd55b50&scene=21#wechat_redirect)  

							  
  

								[ 2023年（12月）手机挑选推荐攻略 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650935891&idx=2&sn=2c87a618f2975e7d5fecef5d2305ad94&chksm=8bac5eacbcdbd7ba77a92ac2e439d211191f36fba205b7eec7c2f0888eb25ed19c3ba9a05126&scene=21#wechat_redirect)  

							  
  

								[ 【LSP专享】嗯这舞蹈绝绝子了6V ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650935891&idx=3&sn=162607663f1d24217a2aa1656ea0148f&chksm=8bac5eacbcdbd7ba41c4c3d1eb396adf4bf2a97af7bb96d9996435d6a2d2aa2018861ebd731d&scene=21#wechat_redirect)  

							  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
  
