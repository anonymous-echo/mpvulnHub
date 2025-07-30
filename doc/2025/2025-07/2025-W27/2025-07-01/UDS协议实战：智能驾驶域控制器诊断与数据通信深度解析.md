> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247556291&idx=2&sn=fdf1d0a37c4a8c35b15b440038230b36

#  UDS协议实战：智能驾驶域控制器诊断与数据通信深度解析  
 谈思实验室   2025-06-30 10:52  
  
点击上方蓝字  
谈思实验室  
  
获取更多汽车网络安全资讯  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247555689&idx=3&sn=d7aee101252438f5f85ed134b1fc05f1&scene=21#wechat_redirect)  
  
在智能驾驶车辆高度复杂的电子架构中，域控制器作为核心计算节点，集成了感知、决策、控制等关键功能。然而，随着自动驾驶等级的提升，域控制器的复杂度呈指数级增长，传统的诊断手段已无法满足其深度诊断需求。如何高效、精准地获取域控制器状态、定位故障，乃至进行远程升级和维护，成为智能驾驶系统稳定运行的关键。  
  
UDS（Unified Diagnostic Services）协议作为ISO 14229-1国际标准定义的诊断通信协议，为这一挑战提供了完整的解决方案。它不仅是智能驾驶域控制器开发、测试、生产和售后维护的"诊断之眼"，更是连接控制器与外部世界进行数据交互的"标准化门户"。  
  
本文将从智能驾驶域控制器的实际应用角度，深度解析UDS协议的核心服务，揭示如何利用UDS实现高效的控制器诊断与数据通信。  
  
**01**  
  
**UDS协议架构：域控制器诊断的"统一语言"**  
  
  
**1.1 UDS协议在智能驾驶系统中的定位**  
  
UDS（Unified Diagnostic Services）是ISO 14229-1国际标准规定的汽车电子控制单元（ECU）诊断协议。在智能驾驶域控制器架构中，UDS协议位于通信协议栈的关键位置：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlKR5Jp1icKgicmfUR9a7AkB6HWl9dTHKiarPBIyaCSBuC6iaALCXCZLD3aw/640?wx_fmt=png&from=appmsg "")  
  
图1-1：智能驾驶域控制器通信架构   
  
上图展示了UDS协议在智能驾驶域控制器通信架构中的核心地位。UDS服务位于诊断应用层，通过标准化的接口与外部诊断工具、OTA升级服务器和车厂诊断系统进行通信，为智能驾驶系统提供统一的诊断和数据交互能力。  
  
**1.2 UDS通信机制**  
  
UDS通信遵循Client-Server模式：诊断工具（Client）发送服务请求，域控制器（Server）处理后返回响应。每个UDS服务都有唯一的服务标识符（SID）。  
  
下图展示了UDS请求-响应通信的基本流程，诊断工具发送包含SID、子功能和数据的请求，域控制器根据处理结果返回肯定响应（SID+0x40）或否定响应（0x7F+原SID+错误码）。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlR38Vkic5erqYCOHzGZ3XlhqnIACAJ0ravD3Sw0kLutMXKicH8NNnLSIg/640?wx_fmt=png&from=appmsg "")  
  
图1-2：UDS请求-响应通信流程   
  
**02**  
  
**UDS核心诊断服务在智能驾驶中的深度应用**  
  
  
**2.1 诊断与通信管理服务**  
  
2.1.1 诊断会话控制 (SID: 0x10)  
  
诊断会话控制是UDS协议的核心服务，决定了域控制器当前可访问的功能范围：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOluhpqHaPCOfuROVpC69lURicpTapLL0KSEjLOL2dbdK88jKVtkl2vpzQ/640?wx_fmt=png&from=appmsg "")  
  
图2-1：诊断会话控制状态图 - 展示三种会话模式的转换关系和功能特点  
  
**智能驾驶应用场景：**  
  
默认会话 (0x01)：车辆正常运行时的诊断模式  
  
- 读取基础故障码  
  
- 获取系统版本信息  
  
- 监控基本运行状态  
  
  
  
扩展诊断会话 (0x03)：开发测试和深度诊断  
  
- 读取传感器原始数据（摄像头图像、雷达点云、激光雷达距离）  
  
- 获取算法中间变量（目标检测置信度、路径规划参数）  
  
- 激活特殊测试功能（传感器校准、算法debug模式）  
  
  
  
编程会话 (0x02)：OTA升级和参数标定  
  
- 域控制器固件升级  
  
- 算法模型更新  
  
- 传感器标定参数写入  
  
  
  
**2.1.2 ECU复位控制 (SID: 0x11)**  
  
下图显示了UDS复位服务的两种主要类型及其在域控制器中的具体执行流程。硬复位模拟完全断电重启，需要重新初始化所有硬件和软件组件；软复位仅重启软件层面，保持硬件状态不变，适用于算法模块的快速恢复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlKoxVDVNgjes2iccuJ4KXI17z42Tn73jfAoHvmQun4SBYp6W1KGibgeQw/640?wx_fmt=png&from=appmsg "")  
  
图2-2：ECU复位控制流程 - 对比硬复位和软复位的执行流程  
  
智能驾驶应用场景：  
  
- 硬复位：验证域控制器冷启动性能，测试自动驾驶系统的启动时间  
  
- 软复位：算法模块异常后快速恢复，避免影响其他功能模块  
  
  
  
**2.1.3 安全访问控制 (SID: 0x27 & 0x29)**  
  
以下流程图展示了UDS安全访问的Seed-Key认证机制，域控制器内置的硬件安全模块负责生成随机Seed值和验证Key值，确保只有获得授权密钥算法的诊断工具才能访问高级功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOljKmLnRz9WSGCKIxic7Ebmia03Vg2RF8pdQPO0HsUdEf8cXx5ibgwziaudg/640?wx_fmt=png&from=appmsg "")  
  
图2-3：Seed-Key安全访问流程 - 展示完整的安全认证交互过程  
  
**2.2 数据传输服务**  
  
**2.2.1 数据标识符读取 (SID: 0x22)**  
  
下图展示了UDS数据读取服务的DID分类体系，从系统信息、传感器数据、算法状态到诊断数据的完整层次结构，每种DID都有特定的应用场景和数据格式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlshzicCsuNyY4PDO2MMEhyVCgurfRTMicDia3zS54tnDCVctibln937XFOw/640?wx_fmt=png&from=appmsg "")  
  
图2-4：数据标识符读取分类 - 展示DID分类体系和典型应用场景  
  
**2.2.2 数据标识符写入 (SID: 0x2E)**  
  
智能驾驶域控制器典型写入场景：  
  
下图展示了UDS数据写入服务在智能驾驶域控制器中的三大应用领域：传感器标定参数的精确写入、算法配置参数的动态调整，以及各种ADAS功能的使能控制。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlbFEum71m4TXE9WyRlnB1zXePwTiaammwPZgwIE1eZRnOunCunqb75Iw/640?wx_fmt=png&from=appmsg "")  
  
图2-5：数据标识符写入应用 - 展示三大写入应用领域  
  
**2.3 故障码诊断服务**  
  
**2.3.1 DTC信息读取 (SID: 0x19)**  
  
下图展示了符合ISO 14229标准的UDS DTC读取服务架构。左侧显示了0x19服务的主要子功能，右侧展示了智能驾驶域控制器中典型的DTC分类体系，包括传感器故障、算法异常和通信故障等类别。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlUAzw2MlyC8ZBiaA7Tcbib2vhAJrnrVIicMprzTomBVEJiasDibRQddg3HXQ/640?wx_fmt=png&from=appmsg "")  
  
图2-6：DTC读取服务架构 - 展示UDS DTC服务体系和智能驾驶DTC分类  
  
**2.3.2 完整诊断流程示例**  
  
下图展示了智能驾驶域控制器的典型诊断流程，从建立扩展诊断会话开始，通过TesterPresent保持连接，依次进行系统信息读取、故障码诊断、实时数据获取和传感器自检，最后通过硬复位结束诊断流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlUU79Z6yLhM4iaO1UC33ADK5RXTib8eSXTNKJguR0iaD7WsPZlarvwzcQw/640?wx_fmt=png&from=appmsg "")  
  
图2-7：完整诊断流程示例 - 展示从建立会话到复位结束的完整诊断过程  
  
**2.4 远程例程控制服务**  
  
**2.4.1 例程控制 (SID: 0x31)**  
  
下图展示了UDS例程控制服务的三种子功能及其在智能驾驶域控制器中的具体应用。例程控制允许远程启动复杂的测试序列，从传感器标定到算法性能测试，再到系统级自检程序的全面覆盖。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlicicZicVDDg1k0fiboGXgiaFrrt1bXkelm7pcTelFJSucibF4N5Gm6icpibmyg/640?wx_fmt=png&from=appmsg "")  
  
图2-8：例程控制服务 - 展示例程控制的子功能和应用场景  
  
**03**  
  
**UDS在智能驾驶域控制器全生命周期中的应用**  
  
  
**3.1 开发阶段应用**  
  
下图展示了智能驾驶域控制器在产品开发各阶段中UDS协议的具体应用，从需求分析阶段的UDS服务定义，到性能优化阶段的诊断功能调优，UDS贯穿整个开发生命周期。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOl2q83MaT4Aa7RpXNGgicEfDvT8eBZTb9c70xRKYHF0kxoXJNUXHx5abg/640?wx_fmt=png&from=appmsg "")  
  
图3-1：开发阶段UDS应用时间线 - 展示产品开发各阶段的UDS应用重点  
  
**3.2 生产制造阶段**  
  
下图展示了生产线上UDS协议在EOL（End of Line）下线检测中的完整应用流程，从固件刷写到最终的故障注入测试，确保每台域控制器出厂前的功能完整性和质量可靠性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlRiaBkwYUwfCxZfNnn88IeOkTB4SPiacb4ia4W2gArHhbXDhLXJ8pMJQjw/640?wx_fmt=png&from=appmsg "")  
  
**3.3 售后服务阶段**  
  
下图展示了售后服务中UDS协议的两大应用场景：传统的车辆进厂诊断流程和现代的远程OTA升级服务。左侧显示了从故障检测到维修验证的完整售后诊断链条，右侧展示了从安全认证到系统验证的OTA升级全流程。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlQTLuPnYQgDRibDeeHR5GcZpx1ictWAbc24I5HQxgPPLyM43tic9IraM0Q/640?wx_fmt=png&from=appmsg "")  
  
图3-3：售后服务应用场景 - 展示传统诊断和OTA升级两大服务场景  
  
**04**  
  
**UDS协议实施的技术要点与注意事项**  
  
  
**4.1 功能安全考虑**  
  
在智能驾驶域控制器中实施UDS协议时，必须考虑功能安全要求：  
  
下图展示了UDS功能安全设计的四个核心维度，从诊断通信的完整性保护，到安全访问的多重控制，再到故障检测的实时监控和安全状态的动态管理，构建了完整的UDS安全防护体系。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlu9aCFzKicO0tb0u8jJSTplicDw5EXhlYpDSibqiafvzSHAyrblAoWibAIBQ/640?wx_fmt=png&from=appmsg "")  
  
图4-1：UDS功能安全设计 - 展示功能安全的四个核心维度  
  
**4.3 标准化与兼容性**  
  
下图展示了UDS协议标准化实施的四个关键维度，从严格遵循ISO 14229国际标准，到满足OEM厂商的特殊需求，再到确保主流诊断工具的兼容性和未来技术的可扩展性。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlCEMK9DTETZw5xr96OJONkaTVzqc8RibXrOg9ricPNIn6bQ4Kqrl3ryVQ/640?wx_fmt=png&from=appmsg "")  
  
图4-3：标准化与兼容性实施 - 展示标准化实施的四个关键维度  
  
**05**  
  
**总结与展望**  
  
  
UDS协议作为智能驾驶域控制器的"数字神经系统"，在整个产品生命周期中发挥着关键作用：  
  
**5.1 核心价值总结**  
  
1. 标准化诊断接口：提供统一的诊断通信标准，降低开发和维护成本  
  
1. 深度故障诊断：支持从系统级到算法级的全方位故障诊断  
  
1. 高效数据交互：实现实时数据读取、参数配置和远程控制  
  
1. 安全可靠通信：内置安全机制，保障诊断通信的安全性  
  
1. 全生命周期支持：覆盖开发、生产、售后的完整应用场景  
  
  
  
**5.2 未来发展趋势**  
  
下图以时间线的形式展示了UDS协议在智能驾驶领域的发展演进路径，从当前基于CAN的传统应用，逐步向5G网络、AI辅助和数字孪生等前沿技术领域扩展。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlTodnuPNTT7A5Nh8IRMQQG3dGAQvibKE9gcZQcbTq15ucFrQDz4ZKFvA/640?wx_fmt=png&from=appmsg "")  
  
图5-1：UDS协议未来发展趋势 - 展示从当前到长期的技术发展路径  
  
随着智能驾驶技术的不断发展，UDS协议也将持续演进，为更复杂的域控制器系统提供更强大的诊断和通信能力。掌握UDS协议的深度应用，将是智能驾驶系统工程师的核心竞争力之一。  
  
**附录**  
  
附录A：UDS服务标识符(SID)快速参考表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOlvUfQZW0ryQ2zyg2CUjdZWAk93KMK3BjSrSOo9ic5wK1icS4ia5gFNz34Q/640?wx_fmt=png&from=appmsg "")  
  
附录B：智能驾驶域控制器典型DID定义  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3g8Dklb9Tw9ibgK9PrytgEQbJnEv7aZOl0cKM1NKIKp3uMvcISHDC1IeFAiaj9HTdVE12YChyn79iauKibfxnibdqgw/640?wx_fmt=png&from=appmsg "")  
  
注：本文图片中的DID仅做示意，具体以OEM自行定义为准；  
  
附录C：参考文献与标准  
  
1. ISO 14229-1:2020 - Road vehicles — Unified diagnostic services (UDS) — Part 1: Application layer  
  
1. ISO 14229-2:2016 - Road vehicles — Unified diagnostic services (UDS) — Part 2: Session layer services  
  
1. ISO 15765-2:2016 - Road vehicles — Diagnostic communication over Controller Area Network (DoCAN) — Part 2: Transport protocol and network layer services  
  
1. SAE J1979 - E/E Diagnostic Test Modes  
  
1. GB/T 32960 - 新能源汽车远程服务与管理系统技术规范  
  
  
  
**end**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/3g8Dklb9Tw8HZVjn7iagiafDIbic2Se5Pib0H7ILiaEJTVXC73vwiaibOE9qujplXjwE40W7ORv050WAkn4F3WTVzQUfA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**精品活动推荐**  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzIzOTc2OTAxMg==&mid=2247555689&idx=3&sn=d7aee101252438f5f85ed134b1fc05f1&scene=21#wechat_redirect)  
  
  
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
  
  
