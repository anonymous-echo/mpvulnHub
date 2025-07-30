> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523387&idx=2&sn=51d9faa28849e3f10c23498b89c880d0

#  CISA和FBI联合发布关于减少现代软件开发中内存安全漏洞的指南  
 代码卫士   2025-06-26 10:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
    
聚焦源代码安全，网罗国内外最新资讯！  
  
**作者：TUSHAR SUBHRA DUTTA**  
  
**编译：代码卫士**  
  
**CISA和FBI联合发布一份关于减少内存安全漏洞的综合指南。内存安全漏洞被视作当前最持久也最危险的软件漏洞类型。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSZVXfR0ju8yz6BT5GKYrGZQFmylymiaH907l0Vo0Qd6A1Da53m4d04nR1iahibpG6jrqQNI4bJqzasQ/640?wx_fmt=png&from=appmsg "")  
  
  
《内存安全语言：减少现代软件开发中的漏洞》文档发布于2025年6月，是美国通过主动安全措施增强国家网络安全基础设施的一个关键里程碑。   
  
数十年来，内存安全漏洞一直侵扰着软件系统，它们可造成灾难性后果，大大突破了理论上的安全担忧范围。“心脏出血”漏洞影响全球80多万个访问量最大的网站，可导致敏感的个人信息被盗，其中包括数百万份医院病患数据。同样，BadAlloc 漏洞显示了内存安全问题带来的深远影响，它影响嵌入式设备、工控系统以及超过1.95亿台设备，因此对国家安全和关键基础设施造成威胁。  
  
这些实践都凸显了亟需采取系统性方法从源头消除内存安全漏洞的，而非仅仅依赖于部署后的安全措施。Defense.gov的分析师和研究人员发现，内存安全漏洞构成了主流软件平台中比例惊人的安全问题。  
  
这份新发布的指南提到，2019年开展的一项研究表明，66%的 iOS 12 中的CVE漏洞以及71%的 MacOS Mojave 中的CVE漏洞是内存安全问题。更令人担忧的是，谷歌 Project Zero 团队分析发现，遭实际利用的75%的CVE漏洞是内存安全漏洞，在2021年发现的58个在野利用0day漏洞中，67%的漏洞属于这一类别。  
  
指南强调称，内存安全语言体现了软件安全领域中的一种范式转变，即从响应式安全措施转变为从设计上主动防御漏洞。和严重依赖于开发者自律和开发后分析工具的传统工具不同，内存安全语言如 Ada、C#、Delphi/Object Pascal、Go、Java、Python、Ruby、Rust 和 Swift 将安全机制直接嵌入语言架构中。  
  
这种设计即安全的方式与CISA更广泛的设计即安全原则一致，后者提倡默认减少漏洞类型，而非在部署后修复。该文档通过真实案例（其中最值得注意的是安卓战略性转向内存安全语言），提供令人信服的内存安全语言的有效性证据。2019年，76%的安卓系统漏洞是内存安全问题，反映了在主要使用内存不安全语言开发的项目中典型的漏洞分布特征。       
  
然而，在所有新的开发工作中优先使用内存安全语言尤其是 Rust 和 Java，同时维护现有的代码库，安卓团队取得了令人瞩目的成绩。截止到2024年，内存安全语言所占比例已下降到只有24%，这是之前内存安全方法所无法比拟的巨大进步。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSZVXfR0ju8yz6BT5GKYrGZjibNFx5N4rXW44jqMgCy42IFHd8fXvssjXoXP5aQvQQqddGd5u4B4mA/640?wx_fmt=gif&from=appmsg "")  
  
  
**内存安全机制的技术实现**  
  
  
  
该指南深入分析了内存安全语言从技术机制层面防御所有漏洞类型的有效性。  
  
内存安全语言防御的核心在于三个基础性安全特性，它们在语言层运行，在程序执行过程中出现内存管理不当问题前就进行防御。边界检查是防御缓冲溢出攻击的第一道防线，该攻击类型是最常见也最危险的内存安全漏洞。在传统的内存不安全语言中，程序员必须手动确保仍然能够在所分配的边界中访问内存。  
  
简单的编程错误可导致程序越界写数据，可能覆写邻近内存并损坏关键的数据结构。内存安全语言通过自动化边界检查消除了这一风险，从而阻止内存越界访问问题。一些语言通过类型安全机制基于数据类型限制操作的方式，执行这一防御机制，确保对象的边界和行为在创建时是已知的并在生命周期内执行。  
  
内存安全语言通过两种机制实现内存管理：垃圾回收机制和严格的所有权模型。垃圾回收机制在Go和Java等语言中实现，它通过一个后台内存管理引擎自动处理内存分配并定期回收不再被程序变量引用的内存。这种机制通过确保内存解除分配后不可被访问，消除了释放后使用漏洞。  
  
而Rust等语言执行严格的所有权和借用规则，确保只有数据所有人才能在合适的实际修改数据，当内存不再拥有所有人时就会被自动释放。这两种方式均阻止了侵扰传统语言的人工内存管理错误。  
  
数据竞争预防机制专门应对并发环境下的内存安全问题——当多线程同时访问同一内存位置且至少一个线程执行写操作时会引发内存损坏，导致程序行为不可预测并产生安全漏洞。  
  
内存安全语言在语言层面实现防护机制，阻止异步并发访问，确保未在程序员明确突破安全预设的情况下，不会发生数据竞争。在现代多线程应用中，传统的异步方式通常是不正确的，内存安全语言的这一防护机制尤为重要。  
  
指南中提到，2016年微软近70%的CVE漏洞与内存安全问题有关，而近年来这一比例下降到约50%左右，尽管内存安全漏洞仍然占据安全补丁的重要比例。这一趋势表明，虽然内存安全实践取得的进展已经产生了一些好处，但使用内存安全语言能进一步减少这一庞大的漏洞类型。  
  
这些安全机制的技术实现反映了从响应式安全措施到主动漏洞防御的根本性转变。通过将安全控制直接嵌入语言架构中，内存安全语言从根本上消除了对开发者自律和开发后分析工具的依赖——事实证明它们不足以全面解决内存安全问题。  
  
该指南不仅增强了安全成果，还减少了开发团队的负担，使他们能够专注于特性开发而非不断修复应在语言层面解决的内存管理复杂性。  
  
****  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[Chrome 131 更新修复高危内存安全漏洞，其中1个获奖5.5万美元](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521859&idx=2&sn=342840d67c1fbf01af15a41ea7621df8&scene=21#wechat_redirect)  
  
  
[CISA：多数重要的开源项目未使用内存安全代码](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247519901&idx=1&sn=32d7347010a5e163854477e5c2232e19&scene=21#wechat_redirect)  
  
  
[美国政府督促开发人员使用内存安全语言](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518933&idx=1&sn=bc26c32481243cbbefbddaff3ad145e8&scene=21#wechat_redirect)  
  
  
[五眼联盟发布关于消除内存安全漏洞的指南](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518310&idx=1&sn=fa3d5f0ab199a0f70069284b938494d2&scene=21#wechat_redirect)  
  
  
[NSA发布软件内存安全问题缓解指南](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514639&idx=1&sn=9aa73d1795f3ecd2c5787fdc8d53d04f&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://cybersecuritynews.com/cisa-releases-guide-to-reduce-memory-safety-vulnerabilities/  
  
  
  
题图：  
Pixabay Licen  
se  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
