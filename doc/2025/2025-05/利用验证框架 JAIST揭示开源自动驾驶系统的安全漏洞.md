#  利用验证框架 JAIST揭示开源自动驾驶系统的安全漏洞   
 谈思实验室   2025-05-29 09:52  
  
点击上方蓝字  
谈思实验室  
  
获取更多汽车网络安全资讯  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247555040&idx=3&sn=d969b879b835b3cfd835876f58cdc385&scene=21#wechat_redirect)  
  
据外媒报道，日本先进科学技术研究所（JAIST）研究人员利用新开发的验证框架，揭示了开源自动驾驶系统在高速行驶和突然切入车辆时的安全限制，这引发了人们对其实际部署的担忧。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw9EENx5oLHhnOhHV2rLhI0T6ZibyzWZQF4GxmqT0ciaialD1xlz9XCkpQfKtKt0AicHDbkpATgZJ98OQw/640?wx_fmt=jpeg&from=appmsg "")  
  
图片来源： JAIST  
  
在这项研究中，JAIST的研究助理教授Duong Dinh Tran及其团队（包括JAIST的Takashi Tomita副教授和Toshiaki Aoki教授）决定对开源自动驾驶系统Autoware进行严格的验证框架测试，以揭示其在关键交通情况下的潜在安全限制。  
  
为了彻底检验Autoware的安全性，研究人员构建了一个特殊的虚拟测试系统。该系统相关论文发表在期刊《IEEE Transactions on Reliability》，并称该系统就像一个自动驾驶汽车的数字试验场。他们使用一种名为AWSIM-Script的语言，模拟各种棘手的交通状况——这些状况是日本汽车安全专家发现的现实世界危险。在这些模拟过程中，一个名为Runtime Monitor的工具会详细记录发生的所有事件，就像飞机上的黑匣子一样。  
  
最后，另一个验证程序AW-Checker分析了这些记录，以验证Autoware是否遵守日本汽车制造商协会（JAMA）安全标准所定义的交通规则。该标准提供了一种清晰、结构化的方法来评估自动驾驶系统（ADS）的安全性。  
  
研究人员重点关注了JAMA安全标准定义的三种特别危险且经常遇到的场景：并道（车辆突然驶入当前车辆的车道）、变道（前方车辆突然变道）和减速（前方车辆突然刹车）。他们将Autoware的表现与JAMA的“谨慎驾驶模型”（代表ADS最低预期安全水平的基准）进行了比较。  
  
这些实验表明，Autoware未能始终满足谨慎驾驶员模型所定义的最低安全要求。正如Tran博士所解释的那样：“使用我们的框架进行的实验表明，与能力强且谨慎的驾驶员模型相比，Autoware无法始终如一地避免碰撞，尤其是在高速驾驶和其他车辆突然横向移动的情况下。”  
  
这些失败的一个重要原因似乎是Autoware对其他车辆运动的预测存在错误。该系统通常预测的是缓慢而渐进的车道变换。然而，当面对快速、激进的车道变换车辆（例如在高速横向速度的切入场景中）时，Autoware的预测不准确，导致模拟中出现制动延迟和随后的碰撞。  
  
有趣的是，该研究还比较了Autoware不同传感器设置的有效性。一种设置仅使用激光雷达，而另一种设置则结合了激光雷达和摄像头的数据。令人惊讶的是，在这些具有挑战性的场景中，仅使用激光雷达的模式通常比摄像头-激光雷达融合模式表现更好。研究人员认为，摄像头系统基于机器学习的物体检测的不准确性可能引入了噪声，从而对融合算法的性能产生负面影响。  
  
这些发现具有重要的现实意义，因为一些定制版本的Autoware已经部署在公共道路上，以提供自动驾驶服务。“我们的研究强调了运行时验证框架如何有效地评估像Autoware这样的真实自动驾驶系统。”  
  
Tran博士指出：“这样做有助于开发人员在系统部署前后识别并纠正潜在问题，最终促进开发更安全、更可靠的公共自动驾驶解决方案。”  
  
虽然这项研究为Autoware在非交叉路口特定交通干扰条件下的表现提供了宝贵的见解，但研究人员计划扩展研究范围，涵盖更复杂的场景，例如交叉路口和涉及行人的场景。他们还计划在未来的研究中探究天气和道路状况等环境因素的影响。  
  
来源：电子工程世界  
  
**end**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8HZVjn7iagiafDIbic2Se5Pib0H7ILiaEJTVXC73vwiaibOE9qujplXjwE40W7ORv050WAkn4F3WTVzQUfA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**精品活动推荐**  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247555040&idx=3&sn=d969b879b835b3cfd835876f58cdc385&scene=21#wechat_redirect)  
  
  
**AutoSec中国行系列沙龙**  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247548574&idx=1&sn=11f37456b4f45c0fdbf795c21e201c03&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247551934&idx=2&sn=50785b76c512a88b30455fc1e8fa188c&scene=21#wechat_redirect)  
  
  
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
  
Upstream、ETAS、Synopsys、NXP、TUV、上海软件中心、Deloitte、中科数测固源科技、奇安信、为辰信安、云驰未来、信大捷安、信长城、泽鹿安全、纽创信安、复旦微电子、天融信、奇虎360、中汽中心、中国汽研、上海汽检、软安科技、浙江大学......  
  
**人员占比**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8HZVjn7iagiafDIbic2Se5Pib0RT6OzSA4O0F8F36otWdvrQxwl9XIt26G3yjOQLcZoODodPdkmbezgQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**公司类型占比**  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8HZVjn7iagiafDIbic2Se5Pib0j2QAibNSg60w1I1YRyibFjDD1aBIzdGCZeGibMiaJ9HgMSLr9vQFZbzlkg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
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
  
  
