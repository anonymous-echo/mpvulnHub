#  ECU自适应模糊测试：用于增强漏洞检测的模块化测试平台方法   
 谈思实验室   2025-05-03 10:28  
  
点击上方蓝字  
谈思实验室  
  
获取更多汽车网络安全资讯  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247554175&idx=2&sn=9ddef07aa3612e1cd1122199353b3b96&scene=21#wechat_redirect)  
  
**01**  
  
**引言**  
  
  
现代车辆是复杂的数字生态系统，其运行和安全依赖于复杂的网络。然而，这些网络中的网络安全漏洞可能会危及道路安全。本文探讨了由 CAN 总线促成的电子控制单元（ECU）之间的关键交互。CAN 总线最初设计用于确保可靠通信，但并未将安全性作为优先考虑因素，这引发了对漏洞的担忧。为应对这些挑战，我们提出了 ARE - GF 框架，该框架结合自动逆向工程来优化模糊测试工作。通过关注常见的 CAN 总线通信模式，此框架可应用于各种车辆模型和其他汽车网络，确保在不同场景下具有广泛的适用性和有效性。通过解决这些漏洞，我们旨在增强现代汽车系统的整体安全性和弹性。本次演示的主要贡献包括：  
  
模块化测试平台：复制车辆网络，以进行精确模拟和漏洞检测。  
  
自适应模糊测试：结合实时 ECU 响应分析，有针对性地发现漏洞。  
  
示例展示：展示测试平台设置、ECU 响应和发现的漏洞，证明该方法的有效性。  
  
**02**  
  
**测试平台设计与实现**  
  
  
模块化测试平台由以下部分组成：  
  
1.车辆网络中的多个 ECU。  
  
2.用于 ECU 通信的 CAN 总线接口。  
  
3.运行定制模糊测试软件的控制单元。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9trs2wzltcKp4UWdn5VeQG1zbXDgL9oJHbJsticRGAqmW5D9z4DPg7ksDPhJsItFiaZEeZ6AsLwcpg/640?wx_fmt=png&from=appmsg "")  
  
图1.将车辆连接到模糊CAN网络的试验台设计  
  
模糊测试软件生成各种格式错误的 CAN 消息，并分析 ECU 的响应，以指导后续的模糊测试迭代。图 1 展示了模块化测试平台的架构，突出了 CAN 总线接口与物理测试平台单元之间的连接。这种设计能够在各种汽车系统上进行灵活测试，并便于集成额外组件，使测试平台能够适应不同的研究需求。为有效利用该测试平台，我们开发了定制的模糊测试软件，实现了我们的自适应模糊测试方法。该软件分两个不同阶段运行：  
  
1.初始模糊测试阶段：软件生成各种格式错误的 CAN 消息，以测试 ECU 对意外输入的弹性。  
  
2.自适应模糊测试阶段：对 ECU 响应进行实时分析，包括错误代码、意外行为和缺失的确认信息，以此指导后续模糊测试迭代的优化，从而更有针对性地发现漏洞。  
  
将动态 ECU 响应纳入模糊测试过程，能够识别传统模糊测试技术可能遗漏的漏洞。通过调整模糊测试过程中使用的通信协议，我们的方法可推广到其他类型的车辆网络，确保采用全面的方法来识别汽车系统中潜在的安全漏洞。  
  
**2.1 模糊测试流程**  
  
自适应模糊测试过程包括多个阶段：  
  
- 初始化模糊测试：设置模糊测试环境，包括模糊测试工具、目标 ECU 和通信接口。  
  
- 生成测试用例：创建各种测试用例，以触发 ECU 中的潜在漏洞。  
  
- 注入测试用例：通过合适的通信通道（如 CAN 总线）将测试用例注入 ECU。  
  
- 监控 ECU 响应：捕获并监控 ECU 的输出、行为以及任何错误消息或异常情况。  
  
- 分析 ECU 响应：分析响应，以确定 ECU 的行为是否符合预期，或是否表现出任何异常行为。  
  
- 是否发现漏洞？：判断是否发现漏洞，并报告以便进一步调查和修复。  
  
- 报告漏洞：生成关于发现漏洞的详细报告，包括其潜在影响。  
  
- 优化模糊测试输入：根据测试结果优化模糊测试输入，以提高测试过程的有效性。  
  
- 迭代模糊测试过程：重复模糊测试循环，直到达到满意的测试效果。  
  
  
  
**2.2 实时 ECU 响应分析和模糊测试自适应**  
  
该过程包括实时 ECU 响应分析，捕获模糊测试输入产生的错误代码、意外行为和缺失的确认信息。主要特点包括：  
  
- 动态分析仪表盘：显示实时 ECU 响应数据。  
  
- 自适应机制：展示模糊测试软件如何根据 ECU 行为动态调整策略，优化测试用例以有针对性地发现漏洞。  
  
  
  
**2.3 发现的漏洞示例**  
  
发现的漏洞展示了它们对车辆安全的潜在影响，并突出了我们的方法相对于传统模糊测试技术的优势。为说明我们方法的有效性，我们总结了使用 ARE - GF 框架识别出的关键漏洞。表 1 概述了这些重要发现，展示了每个漏洞的严重程度和潜在影响。这些示例强调了我们的自适应模糊测试方法在揭示可能危及车辆安全和功能的重大安全缺陷方面的重要性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9trs2wzltcKp4UWdn5VeQGAQUicx8Rl7GM3togZAUiaQ4LDsjgFz8uj9u5phicYonVgdbed8lD1vrdQ/640?wx_fmt=png&from=appmsg "")  
  
表1.使用（ARE-GF）发现的漏洞  
  
**03**  
  
**结论与未来工作**  
  
  
本文介绍了一种新颖的使用模块化物理测试平台对汽车 ECU 进行自适应模糊测试的方法。通过将动态 ECU 响应纳入模糊测试过程，该方法能够更有针对性、更高效地发现漏洞，有助于开发安全且有弹性的汽车系统。模块化测试平台设计允许在各种汽车系统上进行灵活测试，并可轻松扩展以满足未来的研究需求。未来的工作将探索集成更多的通信协议，并进一步实现模糊测试过程的自动化，提高我们方法的可扩展性和稳健性。这将使我们的框架能够应对更广泛的漏洞，并适应汽车网络安全领域新出现的威胁。  
  
来源：  
  
https://mp.weixin.qq.com/s/uAfk6_InTOycp7pzDht9Ig  
  
**end**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8HZVjn7iagiafDIbic2Se5Pib0H7ILiaEJTVXC73vwiaibOE9qujplXjwE40W7ORv050WAkn4F3WTVzQUfA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**精品活动推荐**  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247554175&idx=2&sn=9ddef07aa3612e1cd1122199353b3b96&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247550227&idx=2&sn=544f67cb3a1221819012825152b360da&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247553873&idx=3&sn=df4228b449961ad63694c933d121a948&scene=21#wechat_redirect)  
  
  
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
  
  
