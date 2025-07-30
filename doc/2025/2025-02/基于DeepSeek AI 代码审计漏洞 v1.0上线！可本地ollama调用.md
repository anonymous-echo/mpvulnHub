#  基于DeepSeek AI 代码审计漏洞 v1.0上线！可本地ollama调用   
 谈思实验室   2025-02-06 09:54  
  
点击上方蓝字  
谈思实验室  
  
获取更多汽车网络安全资讯  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbu3V22H9QtksRHsvbYjmWzAGoPygQibfrpdnksKhN98XzxuuQvKOVeRQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**前言**  
  
经过相当的一段时间开发和很多通宵的优化修改，内测，这个工具总算可以把1.0版本拿出来给大家了，同时非常感谢lingview师傅让开发得以顺利，zac(点点)师傅给出了idea，并参与到优化中，非常感谢。  
  
**工具亮点**  
  
结合了污点分析+ast分析+AI分析(两轮不同提示词校验)验证并输出payload  
  
拥有在线和离线两种模式 api调用和本地ollama调用  
  
支持php和java的审计  
  
以及看起来还不错的功能优化调教  
  
**工具截图**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbulCJE8HokD4iaibvWyHjfgCngjj82APoSbPrqqjBy3WQJ0TX2Jhpc29icQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuNa2wAZTyrVkSS0Udpw3yASenZtQYcvAhIBmywluaDD5mg7OL7GK90Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuajOzSlPIQt4HvGwhLPUYmWRtOwsAoZaicvoe9jK6gjTpKBw5DoQxDAw/640?wx_fmt=png&from=appmsg "")  
  
**使用手册**  
  
左上角文件 打开文件将会导入文件夹并自动开始审计  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuJ1icD2c6ymqIbZ3EUbQgYAAxGumOXVnC4SpbrqBYnlvHUXrYjwUryQA/640?wx_fmt=png&from=appmsg "")  
  
在第三页的设置栏我们可以选择在线或者离线模式  
  
在线模式的API key 和url我们比方使用deepseek  
  
https://platform.deepseek.com/api_keys 在开放平台创建key即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuuKF6cB6C2Nf8DkJVMEibMWIyPsXicat3zhcw56v18KcicKxrT3j4BEPZg/640?wx_fmt=png&from=appmsg "")  
  
离线模式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuQVDDbHfFYwOqZKSgwKskKDubpxVO5EYVyLIYXl6LuOFevhXARicJOsg/640?wx_fmt=png&from=appmsg "")  
  
离线模式仅支持ollama 内部写的也是ollama的调用 模型名称是你的ollama list的模型  
  
离线模式提示词可以修改 不过这会间接导致很多问题，包括但不限于 无法正常回显 误报率增加 等等问题 不过改好了的话将会使误报率大大降低 这个是我们提供的 提示词模版:  
```
你是一个代码审计专家用来辅助我判断代码有没有安全漏洞，你的职责是判断我给你的漏洞有没有可控点，我只会给你代码你只需要回答，存在漏洞，不存在漏洞，以及无法判断，不需要解释！！！，不需要你给出修复 防止 等等建议只需要回答，存在漏洞，不存在漏洞，以及无法判断这几个选择 总之回答的 存在漏洞，不存在漏洞，以及无法判断 不需要解释是核心
```  
  
离线模式我们不进行二次校验，并且不推荐和建议大家去进行大项目的离线审计，只建议单代码文件,或者较小体量进行审计，这完全是因为本地大模型GPU的局限性，此外，我们有完全离线模式就是不使用ai 纯污点分析用于快速检索排查  
  
漏洞跳转到代码界面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbupleDoQT962TZLXt7YiaZZjuicDibbLShTUIpB2agy3hVhSU70fSXvPfJA/640?wx_fmt=png&from=appmsg "")  
  
点击漏洞即可跳转  
  
这个搜索是文件内搜索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuR9BuEKPwItEEUKsoibT11LoWC6A7vmGohPXsCLVJKX0H5WBKOUY5Y3A/640?wx_fmt=png&from=appmsg "")  
  
在左上角文件-->搜索是全局关键字搜索  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuNsy0BpQg6Xd6dUVWnia8ic7XygUn8yLNQQBSrz3IlUXDbQcaaW7icz1mA/640?wx_fmt=png&from=appmsg "")  
  
**获取方式**  
  
蓝奏云:https://wwcl.lanzn.com/icRyV2lkqflg  
  
来源： 渗透安全团队  
  
  
**end**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbut5c7Z2DcpDakia1Ow1pvDFt8ic6p5QcDKm3NfXzbIFoJzibxVmM33UXHg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**精品活动推荐**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuEE2fiaBz7lABjqhickQjzGBBiatJsBibaBNebfJia8V9w0oOme8QSwicXDdg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuM37AZIbryWL0NxKkrH2HVWGslqPnRQoR93brpqyNiazbCfyA5TIdw0g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbu3V22H9QtksRHsvbYjmWzAGoPygQibfrpdnksKhN98XzxuuQvKOVeRQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbu7ZR18JjbvdwiaOh4d123oxhz8SWFW5wQZqX6YXibjzgdDyyYxFJoO6icg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbuay32H2NBASHCM8ziby1gm8Juf4d8TFQicp7F74tXGD1W46StXu1VuMhg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**专业社群**  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247535223&idx=1&sn=e30e07a44accd5b0e9ada3d8b537f977&scene=21#wechat_redirect)  
  
**部分入群专家来自：**  
  
  
**新势力车企：**  
  
特斯拉、合众新能源-哪吒、理想、极氪、小米、宾理汽车、极越、零跑汽车、阿维塔汽车、智己汽车、小鹏、岚图汽车、蔚来汽车、吉祥汽车、赛力斯......  
  
**外资传统主流车企代表:**  
  
大众中国、大众酷翼、奥迪汽车、宝马、福特、戴姆勒-奔驰、通用、保时捷、沃尔沃、现代汽车、日产汽车、捷豹路虎、斯堪尼亚......  
  
**内资传统主流车企：**  
  
吉利汽车、上汽乘用车、长城汽车、上汽大众、长安汽车、北京汽车、东风汽车、广汽、比亚迪、一汽集团、一汽解放、东风商用、上汽商用......  
  
**全球领先一级供应商：**  
  
博世、大陆集团、联合汽车电子、安波福、采埃孚、科世达、舍弗勒、霍尼韦尔、大疆、日立、哈曼、华为、百度、联想、联发科、普瑞均胜、德赛西威、蜂巢转向、均联智行、武汉光庭、星纪魅族、中车集团、赢彻科技、潍柴集团、地平线、紫光同芯、字节跳动、......  
  
**二级供应商(500+以上)：**  
  
Upstream、ETAS、Synopsys、NXP、TUV、上海软件中心、Deloitte、奇安信、为辰信安、云驰未来、信大捷安、信长城、泽鹿安全、纽创信安、复旦微电子、天融信、奇虎360、中汽中心、中国汽研、上海汽检、软安科技、浙江大学......  
  
**人员占比**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbueicxviao0Q1hwEciaVcY8rdGPWHzP6I366AKdJibg1I1FnOYYzXYebvNiaw/640?wx_fmt=png&from=appmsg "")  
  
  
**公司类型占比**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8DIibR5JCn4zBgKDhND9fbukLoArAlL4QmuJtReb1aZt3BHysKnPQjR0KfUZQoWyqnupu6I6uW9iaA/640?wx_fmt=png&from=appmsg "")  
  
  
**更多文章**  
  
# 不要错过哦，这可能是汽车网络安全产业最大的专属社区！  
  
[关于涉嫌仿冒AutoSec会议品牌的律师声明](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247531034&idx=2&sn=e466ca3e7c2927a91dd9a81be705afe1&chksm=e9273ec1de50b7d7f540ae2e4c255bfb42f842228a87f7dbc65297027a878544a9e796e09cf6&scene=21#wechat_redirect)  
  
  
[一文带你了解智能汽车车载网络通信安全架构](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247517280&idx=2&sn=8bfafb17871598c9cc0041bc9ee5f65d&chksm=e927c0bbde5049ad8cdb3647f6cdfce00c2db7a7b484941027bb7edf3128e4eaa74d6727dd46&scene=21#wechat_redirect)  
  
  
[网络安全：TARA方法、工具与案例](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247502093&idx=1&sn=ec4b373a33ca04d79afbb0b0b880bd4e&chksm=e9278dd6de5004c01bdd83ad0dd89c3549c7ae2ceb362959dbcb159324b2593d70bce78d82a9&scene=21#wechat_redirect)  
  
  
[汽车数据安全合规重点分析](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247519068&idx=1&sn=78c66e13bd8798afd46c766b8f18abe7&chksm=e927cf87de504691c816f78b55daf93bdfb72fc1cb870d926de8b471eb3e1be61058498327b1&scene=21#wechat_redirect)  
  
  
[浅析汽车芯片信息安全之安全启动](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247512151&idx=1&sn=7fabbeeec206ce615a5a3c574bed4c43&chksm=e927f48cde507d9ab6bfd4b8389b5eafea37586707682bfe60f294feb54e1c36cb07bad4d26d&scene=21#wechat_redirect)  
  
  
[域集中式架构的汽车车载通信安全方案探究](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247519952&idx=2&sn=709860de942501f20e923d15330ced9a&chksm=e927ca0bde50431df0b47ad1a2da63bf98ee637c9c00482145fbdb8755851b61421357aab4bf&scene=21#wechat_redirect)  
  
  
[系统安全架构之车辆网络安全架构](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247520446&idx=1&sn=27e10e455264cecb2a1b49d91484d036&chksm=e927d465de505d73c59a6fb4cb066c7c7d07a96ef49a841ffe598c23d28be545c5874dec7de4&scene=21#wechat_redirect)  
  
  
[车联网中的隐私保护问题](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247521010&idx=1&sn=94ef379e2b877551093a869cf9d4897e&chksm=e927d629de505f3f3cbc102682f7a21a82372108776d3484d8ce619f7db1aae0ab0a001b9b41&scene=21#wechat_redirect)  
  
  
[智能网联汽车网络安全技术研究](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247521302&idx=1&sn=01e9311cb2c84f3e64902abf5f6e7a9e&chksm=e927d0cdde5059db5fe18c5e27f830bbb6ea6df327088082e7844aa056b05f840ad4cf6e3b5a&scene=21#wechat_redirect)  
  
  
[AUTOSAR 信息安全框架和关键技术分析](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247521661&idx=1&sn=a72381e326e3a226059954c74698e0dd&chksm=e927d1a6de5058b0297b91ba77fcf34bd3c581476a0790c5e0cfbcbe026b5a7c27d700bfb1ca&scene=21#wechat_redirect)  
  
  
[AUTOSAR 信息安全机制有哪些？](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247522056&idx=1&sn=bbd03def212d085f533e0301f8c86f18&chksm=e927d3d3de505ac57099d5e42fb6726cf152de9aaa9590b095895874e7a4cc806abc84cc4ebf&scene=21#wechat_redirect)  
  
  
[信息安全的底层机制](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247522886&idx=1&sn=77103702d98e3788beae34b8ea3c31d0&chksm=e927de9dde50578b3dce0bba65599da38844310edd8554f43c9f1c354eaa0487b7c8b4f65c3c&scene=21#wechat_redirect)  
  
  
[汽车网络安全](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247523567&idx=1&sn=1b1d83f339de81a0dc396dd0bd6e6893&chksm=e927d834de50512246f63e47a32f7b934e64eb2b6138053ef43485b871736a122db1340bc437&scene=21#wechat_redirect)  
  
  
[Autosar硬件安全模块HSM的使用](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247527177&idx=1&sn=984bfc845ef51ec1f32cd12d37430621&chksm=e9272fd2de50a6c4013f84ed2257f634a505a04a27b4b27c30e5af4492d5fc3b0099216b1f7d&scene=21#wechat_redirect)  
  
  
[首发!小米雷军两会上就汽车数据安全问题建言：关于构建完善汽车数据安全管理体系的建议](http://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247519331&idx=1&sn=925d48164f1c7d2d109ee433cde6805b&chksm=e927c8b8de5041aea58f73aed311cdd3bf913bbb73d8e175ac80ae643d944709e06ec418fb52&scene=21#wechat_redirect)  
  
  
