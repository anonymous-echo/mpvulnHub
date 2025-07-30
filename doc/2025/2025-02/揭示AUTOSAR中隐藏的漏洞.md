#  揭示AUTOSAR中隐藏的漏洞   
 谈思实验室   2025-02-02 11:01  
  
点击上方蓝字  
谈思实验室  
  
获取更多汽车网络安全资讯  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhhiaq2DHiauFEicaGWX2hm03WyL4E5x3zwticyxqtz8icVt1pale8he3odbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
AUTOSAR是一个普遍采用的软件框架，用于各种汽车零部件，如ABS, ECU,自动照明、环境控制、充电控制器、信息娱乐系统等。AUTOSAR的创建目的是促进汽车零部件之间形成标准接口，可以在不同制造商之间互通。  
  
因此，任何配备微控制器(MCU)的汽车零部件都应符合AUTOSAR的规定。  
  
AUTOSAR标准不仅管理用于模块间通信的数据格式，还规定了这些模块的标准API。在汽车行业内使用的AUTOSAR平台有两个版本：Classic和Adaptive。  
  
Adaptive平台是为高性能设备量身定制的，例如信息娱乐系统或高级驾驶辅助系统(ADAS)，这些设备通常在Linux或QNX等资源丰富的操作系统上运行。另一方面，Classic平台部署于运行在微控制器单元裸板(MCU)上的低性能设备中，包括ABS, EBD, 安全气囊控制单元、车身控制模块、传输控制模块等系统。  
  
虽然AUTOSAR是一个稳健而可靠的开发框架，但它并非没有潜在的错误和漏洞。在对AUTOSAR文件进行内部分析时，我们偶然发现了一个特别有趣的漏洞，这个漏洞可能会带来很大的安全风险。代码中的缺陷并不是由于AUTOSAR本身造成的，而是对AUTOSAR使用不当的结果。  
  
在本文中，我们打算深入研究和剖析这个具体的案例。  
  
**01**  
  
**AUTOSAR Classic固件开发**  
  
  
在大多数情况下，固件是利用两家领先的AUTOSAR软件提供商(Vector和Elektrobit)提供的工具链开发的。  
  
Vector和Elektrobit都提供了配置工具和SDK，其中包括标准AUTOSAR模块的预构建实现，如MicroSAR OS运行时、CAN接口、NVM API、诊断模块、加密和内存接口等。这种被称为基本软件(Basic Software,简称BSW)的SDK是以中间件方式执行，因此不能在目标硬件上独立运行。  
  
除了BSW之外，还有一套被称为微控制器抽象层(Microcontroller Abstraction Layer,简称MCAL)的驱动程序和库，用于对硬件的访问。每个打算将其MCU用于汽车行业的硬件制造商都提供了适用于其MCU的AUTOSAR MCAL。例如，有来自博世、恩智浦、瑞萨和英飞凌的MCAL。MCAL驱动程序和库也需要遵循AUTOSAR标准，以确保BSW可以与任何硬件制造商的MCAL一起使用。  
  
新固件的开发通常从配置工具开始。在这里，开发人员构建要使用的硬件平台，为他们的项目选择所需的MCAL和BSW模块，然后在所有模块之间建立连接。例如，开发人员可以指定BSW中的CanIf模块应该使用哪个MCAL的CAN接口。一旦配置阶段完成，配置工具就会生成源代码，这些源代码本质上是MCAL和BSW的一个子集。  
  
生成源代码之后，可以使用任何编译器或集成开发环境(IDE)对其进行编译，然后再将其安装到目标设备上。由配置工具输出的源代码已经包含了设备以默认行为操作所必需的一切。因此，开发人员可能不需要对所生成的代码进行任何修改。在BSW层之上的任何自定义代码往往都是最小化了的，通常占固件总大小的10%以下。  
  
**02**  
  
**基于AUTOSAR的固件漏洞**  
  
  
在我们进行红队渗透测试的过程中，我们获得了基于AUTOSAR的固件进行安全评估。从攻击者和渗透测试者的角度来看，基于AUTOSAR的文件的潜在攻击点非常有限。该模块的源代码非常可靠，始终经过代码审查和漏洞分析。  
  
关于常规漏洞和通用缺陷枚举(CWE)，发现它们的可能性相当小。没有动态内存分配，所有变量要么是全局的，要么是堆栈上的，从而消除了发现double-free或use-after-free等漏洞的机会。汽车代码不执行字符串操作，而只关注二进制解析。因此，通过sprintf, sscanf, strcpy等操作遇到堆栈溢出的可能性在这里是不存在的。  
  
当涉及到潜在的竞态条件漏洞时，AUTOSAR Classic不允许动态任务初始化或动态创建的同步原语。任务和同步事件列表是在配置阶段预先确定的。因此，考虑到静态的、预先配置的任务资源和事件集，自动生成的代码不太可能包含死锁或竞态条件。  
  
因此，我们必须深入研究AUTOSAR框架，了解它的用法和对API的潜在使用不当，特别关注用户如何以可能导致漏洞的方式调用它。  
  
我们在NvM模块中遇到了一组函数：NvM_ReadBlock, NvM_WriteBlock和NvM_RestoreBlockDefaults，这组函数通常用于在NVM中加载和存储设备设置（如EEPROM, NAND, NOR内存等）。  
  
通过对NVRAM管理器规范中的函数原型进行研究：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhnX05qnSRNib4B5zVUP9ic2lmkRgK3ibLcuS3NGc4wyD45VHKZxvYmzrTQ/640?wx_fmt=png&from=appmsg "")  
  
很明显，这些函数缺少缓冲区大小检查，仅使用块ID来确定在配置阶段配置的特殊块表中的数据大小。换句话说，用户有责任包含在写入时验证保存在NvM块中的数据大小是否合适的代码。同样，当从NvM块中读取数据时，用户有责任提供足够大的缓冲区，因为NvM_ReadBlock只是根据NvM块的大小简单地覆盖缓冲区。  
  
因此，这样的API调用可能会导致越界(Out of Bounds, 简称OOB)读取或写入。根据作为NvM_DstPtr/NvM_SrcPtr传递的缓冲区类型，可能会出现各种问题：  
  
- 如果用户提供了一个小的堆栈变量，但读取了一个大的NvM块，NvM_ReadBlock将在堆栈变量之外写入数据，这会导致堆栈损坏，并可能为远程代码执行(Remote Code Execution,简称RCE)打开大门。  
  
- 如果提供的变量是全局变量，NvM_ReadBlock将覆盖邻近的全局变量。这可能会导致代码中出现未定义的行为。  
  
- 如果用户为NvM_WriteBlock提供了一个小的堆栈或全局变量，将导致NvM_WriteBlock读取变量外的数据，并将随机数据存储到NVM中。  
  
  
  
利用这种方法，我们发现了一个有趣的由于AUTOSAR API使用不当导致缓冲区溢出漏洞的案例。  
  
**03**  
  
**测试设备在发现基于AUTOSAR的漏洞线**  
  
  
让我们看一下我们遇到的漏洞的简化版本：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhCROalRkZKglPhVZ2J6tfialKhjHAwyNHYAficFDyGLBFsmdtERiaYXYLw/640?wx_fmt=png&from=appmsg "")  
  
NvM_ReadBlock将从NVM读取0x110字节，然后将其写入myVar的位置。虽然NvM_ReadBlock会准确地写入myVar的值，但之后它仍将继续用不可预测的值覆盖邻近的全局变量。  
  
在我们发现的案例中，NvM_ReadBlock被设置为在堆栈上执行越界写入操作，这可能会覆盖函数的返回地址。  
  
在这个具体案例中，对易受攻击函数的调用被MCU复杂的自定义工作流程所掩盖。然而，它仍然是可触发的，并且确实导致了执行崩溃。  
  
**04**  
  
**缓解威胁**  
  
  
代码生成之后，管理源代码中与NvM API一起使用的变量大小就完全是开发人员的责任了。因此，AUTOSAR开发人员应当尽一切努力在配置器中对齐变量和NVM块的大小。AUTOSAR开发人员还应当避免修改生成的代码，除非他们完全理解有关NVM块大小的约束。  
  
此外，没有NVM函数可以提供NVM块的大小来执行如下检查：assert(sizeof(myVar) == NvM_BlockSize(Block_ID))；这是因为块大小被硬编码到NvM模块配置中，并被视为内部数据。  
  
即使在使用AUTOSAR这样的标准化框架时，在某些情况下，也可能无意中引入重大的内存漏洞。为了减少这种情况，强烈建议采用持续的质量保证措施和定期的渗透测试。  
  
**05**  
  
**总结**  
  
  
虽然AUTOSAR为汽车软件开发提供了一个稳健而标准的框架，但由于使用不当，特别是在NvM API的变量管理中，仍然可能出现潜在的漏洞。随着汽车技术越来越复杂，有必要通过持续的质量保证和定期的渗透测试来加强软件安全性。这些实践，加上对正在使用的框架的深刻理解，可以帮助开发人员降低潜在的安全风险，并提高汽车系统的整体安全性。  
  
来源：汽车功能安全  
  
  
**end**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhScaHPz7zZ9aI1JnRpwnaa5DjribYv43IjuOxibQgBbB7pJu7QkHROLYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**精品活动推荐**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhHs3x3eXSmdK1icPsImLnzrsazrUhwZeCNM6AL1dcWt3FOwfdDTvS4Qw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhDWhU5FvMHtFpjuQkjFPEQJYiaoIoB0JGoCYwZUvXCbI6nCD1An4zRuA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhhiaq2DHiauFEicaGWX2hm03WyL4E5x3zwticyxqtz8icVt1pale8he3odbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGh2ia1dmXFnANFq6icT0ekeds1oOetmtiaM8ylY6cGGIwjCCNNry333xRibw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhoJaPZA3ic8fLbQYbUkmyorp9WZTsbehPkO8brUYTwhAN6clUPxGotibw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
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
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhbTiaRVBzE0iaVTR0AIHmHdgrb9UY6iaatJWsRFlGvffSEnSryvricibzibFA/640?wx_fmt=png&from=appmsg "")  
  
  
**公司类型占比**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw8ZhsBNqVmTQa3gTDLmGOGhs1TX5s6Cr8IM3Qq5G9sMcCMwE4SuNKmxduSYWiambabU07Rr639tVnw/640?wx_fmt=png&from=appmsg "")  
  
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
  
  
