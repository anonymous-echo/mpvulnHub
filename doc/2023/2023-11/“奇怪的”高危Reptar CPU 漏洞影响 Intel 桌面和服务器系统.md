#  “奇怪的”高危Reptar CPU 漏洞影响 Intel 桌面和服务器系统   
Sergiu Gatlan  代码卫士   2023-11-15 17:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Intel（英特尔）修复了位于现代桌面、服务器、手机和嵌入式CPU（包括最新的 Alder Lake、Raptor Lake 和 Sapphire Rapids 微架构）中的一个高危CPU 漏洞 (CVE-2023-23583)。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSZbDWoyEzJktEoNrHP3iara0un4lKOkJqia72wad6XdR9ymBDgRIT0auvyTtQ8mkhWAnQxc44mRvmQ/640?wx_fmt=png&from=appmsg "")  
  
  
CVE-2023-23583 漏洞被称为 “冗余前缀问题”，可被用于提升权限、获得对敏感信息的访问权限或处罚拒绝服务状态（对于云提供商而言成本高昂）。  
  
英特尔公司表示，“在某些微架构条件下，英特尔已发现执行用冗余 REX 前缀编码的指令可能会导致不可预测的系统行为，从而导致系统崩溃/挂起，或在一些有限的场景中，可能会导致从 CPL3到CPL0的提权。英特尔认为该问题不会由任何非恶意的真实软件遇到。冗余 REX 前缀不会出现在代码或由编译器生成。恶意利用该漏洞要求任意代码执行。英特尔在受控的实验室环境中，在内部安全验证的有限场景中发现了提权的可能性。”  
  
配备受影响处理器的特定系统，包括具有 Alder Lake、Raptor Lake 和 Sapphire Rapids 的系统已在2023年11月之前收到更新后的微代码，并未发现性能影响或其它问题。  
  
英特尔还发布微码更新，修复了其它CPU中的同一问题。建议用户更新BIOS、系统OS和驱动，从原始设备制造商、操作系统厂商和管理程序厂商处接收最新微码。  
  
另外英特尔还发布了受该漏洞影响的完整CPU列表以及缓解指南。英特尔公司表示，“英特尔建议将受影响处理器尽快更新至受影响处理器表中所列的微码版本，缓解该冗余前缀问题。操作系统厂商也会尽快提供包含这一新微代码的更新。”  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSZbDWoyEzJktEoNrHP3iaranqLdBxRcJwqm743Ihe7dQicQMicuRicoWWX8JMKU0ZPoKUXTibStiaFlT6w/640?wx_fmt=gif&from=appmsg "")  
  
**“非常奇怪的” Reptar 漏洞**  
  
  
  
谷歌的漏洞研究员 Tavis Ormandy 披露称，谷歌内部的多个研究团队如谷歌信息安全工程团队和 silifuzz 团队也独立发现了该漏洞，并将其称为 “Reptar”。  
  
谷歌云副总裁兼首席信息安全官 Phil Venables 解释称，该漏洞与“CPU如何解释该冗余前缀，导致在成功利用后可绕过CPU安全界限”有关。虽然通常而言，冗余前缀应当被忽视，但Ormandy 在测试中发现该漏洞使它们触发“非常奇怪的行为”。  
  
Ormandy 指出，“我们在测试过程中发现了一些非常奇怪的行为。例如，异常位置出现分支、无限制的分支被忽视、处理器不再准确地在 xsave 或调用指令中记录指令指针。这已经可以看作是严重问题的提示，但在实验的几天时间内我们发现，当多个内核触发同一个漏洞时，该处理器将开始报告机器检查异常和中止。”  
  
今年早些时候，谷歌安全研究人员发现了影响英特尔现代CPU的 Downfall 漏洞以及可导致攻击者从 AMD Zen2 CPU 的系统中窃取敏感数据如密码和加密密钥的Zenbleed 漏洞。今天，AMD 还修复了一个可导致恶意人员黑入受 AMD SEV保护的VM以提升权限并获得远程代码执行的 CacheWarp 漏洞。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[堪比Meltdown？几乎所有的现代 CPU 易受“碰撞+功率”侧信道攻击，数据易遭泄露](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247517301&idx=1&sn=dc542520f59c9e8a02450e19d4f0989b&chksm=ea94b51fdde33c09d7d671b9986fa4e910a7208b39f050309c00bb6ef0f7afaa96cc008af9a6&scene=21#wechat_redirect)  
  
  
[虚惊一场？英特尔为几乎所有现代 CPU 发布神秘补丁](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516496&idx=1&sn=abeb68405b9da13d650993ec601fb8b3&chksm=ea94b03adde3392c43f6bd1b06a329aa3f7b78ddbef6ba95f53374665a1407048938901c0e4b&scene=21#wechat_redirect)  
  
  
[新型侧信道漏洞 Hertzbleed 影响所有AMD 和 Intel CPU](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512362&idx=2&sn=8b46a7d7acb584b00292304dfcc7fd67&chksm=ea948040dde30956d4770c1c90d9bf9b7ad1acc876eb83ac63c20987e9f83b6678f23e01c62e&scene=21#wechat_redirect)  
  
  
[麻省理工研究员发现苹果 M1 CPU 中无法修复的新缺陷](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512281&idx=3&sn=1bae3c23b647e073efcb6df3fa15dcce&chksm=ea9481b3dde308a5b6ece11817a148a6d20a38c366288e9c3183f774bd4a6768612fac6f33cb&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/new-reptar-cpu-flaw-impacts-intel-desktop-and-server-systems/  
  
  
题图：  
Pixabay  
 License  
  
****  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
  
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
  
