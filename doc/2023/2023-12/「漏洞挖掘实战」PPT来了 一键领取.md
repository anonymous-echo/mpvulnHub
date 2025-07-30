#  「漏洞挖掘实战」PPT来了| 一键领取   
原创 干货满满的  字节跳动安全中心   2023-12-19 18:12  
  
12月15日，第12期安全范儿技术沙龙「漏洞挖掘与实战」线上圆满结束！来自**字节跳动无恒实验室、字节跳动云安全团队、中孚信息元亨实验室、武汉大学**的4位安全专家，通过多维度、多视角的漏洞挖掘实战案例为线上的白帽师傅们带来精彩演讲。  
  
  
安全范儿技术沙龙**由字节跳动安全与风控发起**，本次沙龙也得到**元亨实验室、补天漏洞响应中心、荣耀安全、京东SRC、平安SRC、小米SRC、讯飞安全**的大力支持！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gAcolpf06Wqtob57rAic0t5Lb74umIeFxUjyCNaY6exPeyOw3J54OPsgdodExUtINGic2VarzewE0ic5dkDibb6dJA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
本场沙龙议题干货满满，可谓手把手带你挖漏洞，观众互动提问不停，讲师金句频出，更有多重豪礼送给云端的观众，错过线上直播师傅们，别急，沙龙的重点回顾安排上了！  
**（文末有抽奖及PPT及视频回放）**  
  
  
  
一同回顾下沙龙精彩议题  
  
  
  
**被忽视的暗面：客户端应用漏洞挖掘之旅**  
  
  
  
首位演讲的专家是来自中孚信息元亨实验室的**首席红蓝对抗安全研究员戴城**，戴城首先通过**信息泄露、白利用、逻辑校验、****缓冲区溢出**四个技术点为大家深入浅出的讲述了常规风险。  
  
之后详细复现了**某IM客户端应用的RCE、某运维平台客户端RCE、某远程服务平台客户端RCE、某视频软件客户端RCE**这四个RCE案例，可谓手把手教线上的师傅们进行漏洞挖掘！直播弹幕也是频频为讲师点赞，更多RCE漏洞细节，也可以通过[中孚安全技术研究](https://mp.weixin.qq.com/s?__biz=Mzg4Nzc3MTk3Mg==&mid=2247488347&idx=1&sn=347f24964b3cd3a81f5a2c05b171ffe5&scene=21#wechat_redirect)  
账号查看。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gAcolpf06Wqtob57rAic0t5Lb74umIeFxerWcibV7JUGgobhgsmOx1CCia6K6Vlf9ecMqS8Td8FFpQzF0DTdggA2w/640?wx_fmt=png&from=appmsg "")  
  
  
**基于ssh蜜罐数据自动生成主机入侵检测规则应用实践**  
  
  
  
字节云安全团队的**安全研究员马骏**  
随后带来第二个演讲，他开篇点题，反入侵的安全策略开发以及安全规则开发  
可能存在一定滞后性，一旦没有及时增补规则，就会出现缺口  
，导致安全隐患，故如何实现自动化生成入侵检测规则也是一项关键动作；  
  
同时马骏提到当前行业对于蜜罐的使用会进行攻击手法的收集；  
若可以将规则开发和高交互蜜罐的利用进行结合，使用SSH蜜罐数据自动生成对恶意行为的检测规则  
，就可以及时发现未知风险行为并告警，提高企业安全水位！接下来针对该出发点，具体介绍了方案的架构设计和应用实践。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gAcolpf06Wqtob57rAic0t5Lb74umIeFxyibCAbSyDbXZgcYsKBo5fCiaGJtXpVPfdpFSkAvZZvqyxBTUcB4trSWQ/640?wx_fmt=png&from=appmsg "")  
  
  
**Fuzzer for IoT : IoT固件自动化漏洞挖掘方法**  
  
  
  
来自**武汉大学的risuxx**，目前研究生在读，拥有多个cve，risuxx首先为大家详细讲述了P2IM、μEmu这两个**针对MCU固件**的模拟工具以及FUZZER，之后**针对路由器固件**的模拟工具FIRMADYNE、FirmAE也讲述了**工具的系统架构和使用方法**。  
  
最后risuxx通过使用binwalk进行解包的过程为大家讲解了一个IoT固件漏洞的挖掘案例。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gAcolpf06Wqtob57rAic0t5Lb74umIeFxPqdqkrRV4mYia4ry8kbRQwic9aERuNWErwlj6pYZ4EbTBeGO3xNGQgZg/640?wx_fmt=png&from=appmsg "")  
  
  
**浅谈SpringWeb路由解析与权限绕过**  
  
  
  
最后是来自无恒实验室的安全工程师成森，首先为大家讲述了Java Web中权限绕过案例，例如权限绕过中很容易想到getReuqestURI/URL方法，但在实际过程中，**框架的路由解析代码往往要比原生的servlet更复杂**，只有深入了解相关框架的解析模式，才能更好避免安全风险。  
  
接着为大家详细剖析了**SpringWeb的路由解析模式演变过程**，最后结合SpringWeb中实际的绕过案例进行分析，也分享了无恒实验室在越权自动化检测中一些优秀实践。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gAcolpf06Wqtob57rAic0t5Lb74umIeFxv8OibmZicvQkgZwIHUr6SiaEm8QWlKjnyoRVKw00RqbO1DjOs3AMgORSw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**获取演讲PPT**  
  
关注【字节跳动安全中心】公众号  
  
回复关键词【**1215安全范儿**】获取PPT  
  
  
**获取沙龙回放**  
  
复制链接观看：  
  
**https://bytedance.larkoffice.com/file/SQtWbILnQonlZ8xFHdicJmzInZg**  
  
  
  
**转发文章参与抽奖**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/gAcolpf06Wqtob57rAic0t5Lb74umIeFxtGVryOMfWKUR2MwibcqlsjvbJ2olo3rWTe2sOabMibSx3dsNKTaNGReg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**✅**  
  
  
至此，字节跳动安全范儿技术沙龙第12期「漏洞挖掘与实战」专场，正式落下帷幕，感谢各位安全从业者、安全爱好者、白帽师傅们，对安全范儿技术沙龙一直以来的关注和支持！让我们下期再会~  
  
  
原文链接直达沙龙回放  
  
