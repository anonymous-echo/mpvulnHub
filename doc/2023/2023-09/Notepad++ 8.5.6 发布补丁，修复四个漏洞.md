#  Notepad++ 8.5.6 发布补丁，修复四个漏洞   
Bill Toulas  代码卫士   2023-09-11 17:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！****  
  
**编译：代码卫士**  
  
**Notepad++ 8.5.7 发布了补丁，修复了多个缓冲区溢出 0day 漏洞。攻击者可利用其中一个漏洞诱骗用户打开特殊构造的文件，执行代码。**  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSrGl704337k3K6gk7pKZz4Gl4DzuP4UwU2NjP2lIILJ9OLgdyt3UHibrWgqqwzf3MAldGDHsKkYKQ/640?wx_fmt=png "")  
  
  
Notepad++ 是一款流行的免费源代码编辑器，支持多种编程语言，可通过插件进行扩展，并且提供多种提高生产力的特性如多标签编辑和语法突出等。GitHub 的研究员 Jaroslav Lobačevski 在过去几个月报送了 Notepad++ 8.5.2 中的多个漏洞。  
  
该研究员在公开安全公告中发布了这些漏洞的验证代码，因此用户应尽快更新该程序。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSrGl704337k3K6gk7pKZz4aX5DLvfnHOibHXrg3reicOspm9W5QsFAVHSh5C6g6goUqHqHKVH8zKQg/640?wx_fmt=png "")  
  
**四个漏洞**  
  
  
研究人员发现的漏洞位于由 Notepad++ 所使用的多种函数和库中存在的堆缓冲写和读溢出漏洞。这四个漏洞如下：  
  
- CVE-2023-40031：位于 Utf8_16_Read::convert 函数中的缓冲溢出漏洞，由关于 UTF16到UTF8 编程会话假设不正确引发。  
  
- CVE-2023-40036：位于 CharDistributionAnalysis::HandleOneChar 中的全局缓冲读溢出漏洞，由基于缓冲区大小的数组索引顺序引发，使用 uchardet 库加剧了这一情况。  
  
- CVE-2023-40164：位于 nsCodingStateMachine::NextState 中的全局缓冲读溢出漏洞，与由 Notepad++ 使用的特定版本的 uchardet 库有关，因对 charLenTable 缓冲区大小的依赖而易受攻击。  
  
- CVE-2023-40166：因在文件语言检测过程中未能检查缓冲区长度，而引发的位于 FileManager::detectLanguageFromTextBegining 中的堆缓冲读溢出漏洞。  
  
  
  
其中最严重的是CVE-2023-40031，其CVSS v3 评分为7.8，可能导致任意代码执行后果。不过一名用户提到，出错消息类型可导致攻击者利用该漏洞执行代码。一条GitHub 提交指出，“虽然从技术上来讲它是一个‘缓冲区溢出’，但实际上只是一个差二错误，几无可能导致任意代码执行后果。”  
  
其余三个漏洞属于低危级别，可用于泄露内部内存分配信息。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMSrGl704337k3K6gk7pKZz4aX5DLvfnHOibHXrg3reicOspm9W5QsFAVHSh5C6g6goUqHqHKVH8zKQg/640?wx_fmt=png "")  
  
**修复方案**  
  
  
虽然博客在8月21日发布了文章和概念验证 exploit，但 Notepad++ 开发团队并未着急做出响应，直到用户社区施加压力，才在8月30日创建了一个公开的issue 证实该问题存在，并在9月3日在主代码分支中推出修复方案。  
  
Notepad++ 8.5.7 现已发布，用户应安装新版本修复这四个漏洞以及变更日志中提到的其它问题。  
  
****  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[2个0day！1个是神秘且已遭利用的 Notepad 0day, 1个影响所有 Docker 版本（含 PoC）](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247490071&idx=1&sn=5911ee4ac3db92df06520b57c9971581&chksm=ea972b7ddde0a26b57d992afb80d24368a2f53d2a9a6fe0b9500d149b0e0c00d528a204f26f6&scene=21#wechat_redirect)  
  
  
[圣战组织黑掉Notepad++站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247486038&idx=2&sn=1631e4e1ba6fbe0bfddc17cd25519a98&chksm=ea973b3cdde0b22a58faff694b0b2fc4ca7ca395153bf931f3b9d387ee5c2219d1ef1c9c74f3&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/notepad-plus-plus-857-released-with-fixes-for-four-security-vulnerabilities/  
  
  
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
  
