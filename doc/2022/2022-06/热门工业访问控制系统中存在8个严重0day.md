#  热门工业访问控制系统中存在8个严重0day   
Ravie Lakshmanan  代码卫士   2022-06-13 18:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTThnHYIF2dOVJhC92dN07wQHk9ibttzwAbMA7hgKBibElAo21BsY4gUmJLicicNOyDajrbhibF9lLmUsg/640?wx_fmt=png "")  
  
Carrier 的 LenelS2 HID Mercury 访问控制系统中存在多达8个0day 漏洞。该系统广泛应用于医疗、教育、交通和政府机构。  
  
  
  
Trellix 公司的安全研究员 Steve Povolny 和 Sam Quinn 指出，“这些漏洞可用于远程开门、锁门、规避警报并破坏日志和通知系统。”  
  
简言之，这些漏洞可被恶意用于获得完整的系统控制权限，包括操纵门锁等。其中一个漏洞 (CVE-2022-31481) 是未认证的远程代码执行缺陷，CVSS 评分为满分10分。  
  
其它漏洞可导致命令执行（CVE-2022-31479和CVE-2022-31486）、拒绝服务（CVE-2022-31480和CVE-2022-31482）、用户修改（CVE-2022-31484）和信息欺骗（CVE-2022-31485）以及实现任意代码写入（CVE-2022-31483）。  
<table><tbody><tr><td style="border-width: 1px;border-style: solid;border-color: windowtext;background: rgb(34, 17, 217);padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE</span></p></td><td style="border-top: 1px solid windowtext;border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: none;background: rgb(34, 17, 217);padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">详情概述</span></p></td><td style="border-top: 1px solid windowtext;border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: none;background: rgb(34, 17, 217);padding: 8px;" width="151"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">Mercury 固件版本</span></p></td><td style="border-top: 1px solid windowtext;border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: none;background: rgb(34, 17, 217);padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVSS 评分</span></p></td></tr><tr><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;background: rgb(221, 221, 221);padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31479</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">未认证命令注入</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="165"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.291</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分 9.0，总分 8.1</span></p></td></tr><tr><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31480</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">未认证拒绝服务</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="165"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.291</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分7.5，总分6.7</span></p></td></tr><tr><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;background: rgb(221, 221, 221);padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31481</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">未认证远程代码执行</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="165"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.291</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分10.0，总分9.0</span></p></td></tr><tr><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31486</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">未认证命令注入</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="165"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.291（无补丁）</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分8.8，总分8.2</span></p></td></tr><tr><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;background: rgb(221, 221, 221);padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31482</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">未认证拒绝服务</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="165"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.265</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分7.5，总分6.7</span></p></td></tr><tr><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31483</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">认证的任意文件写</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="165"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.265</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分9.1，总分8.2</span></p></td></tr><tr style="height:46px;"><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;background: rgb(221, 221, 221);padding: 8px;" width="132" height="46"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31484</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="122" height="46"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">未认证用户修改</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="165" height="46"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.265</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;background: rgb(221, 221, 221);padding: 8px;" width="115" height="46"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分7.5，总分6.7</span></p></td></tr><tr><td style="border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-left: 1px solid windowtext;border-top: none;padding: 8px;" width="132"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">CVE-2022-31485</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="122"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">未认证的信息欺骗</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="165"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">&lt;=1.265</span></p></td><td style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;padding: 8px;" width="115"><p style="text-align:left;line-height: 16px;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(33, 37, 41);font-size: 15px;letter-spacing: 1px;font-family: Helvetica, Arial, sans-serif;">基础分5.3，总分4.8</span></p></td></tr></tbody></table>  
  
LenelS2 用于各种环境中，提供对权限设施的物理访问权限，并和更复杂的构建自动化部署集成。如下由LenelS2出售的 HID Mercury 访问面板受影响：  
  
- LNL-X2210  
  
- LNL-X2220  
  
- LNL-X3300  
  
- LNL-X4420  
  
- LNL-4420  
  
- S2-LP-1501  
  
- S2-LP-1502  
  
- S2-LP-2500, 以及  
  
- S2-LP-4502  
  
  
  
Trellix 表示通过组合利用上述两个缺陷，攻击者可远程获得设备的根级别权限并解锁、控制门，从而破坏系统监控防御措施。  
  
巧的是，美国网络安全和基础设施安全局 (CISA) 发布工业控制安全公告，督促用户将访问面板更新至最新固件版本（CARR-PSA-006-0622）。  
  
CISA 发布安全警报称，“成功利用这些漏洞可使攻击者访问该设备，监控所有发送给且源自设备的通信，修改内建中继，更改配置文件、导致设备不稳定，并且制造拒绝服务条件。”  
  
目前Carrier 已发布缓解措施和固件更新。补丁将尽快发布。  
  
具体可参见 Carrier 发布的安全公告：  
  
https://www.corporate.carrier.com/Images/CARR-PSA-HID-Mercury-Vulnerabilities-006-0622_tcm558-170514.pdf  
  
  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com****  
  
  
  
  
  
  
  
  
  
**原文链接**  
  
https://thehackernews.com/2022/06/researchers-disclose-critical-flaws-in.html  
  
https://www.trellix.com/en-us/about/newsroom/stories/threat-labs/trellix-threat-labs-uncovers-critical-flaws.html  
  
  
  
题图：Pixab  
ay License  
  
  
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
