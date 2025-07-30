#  思科ISE严重漏洞导致攻击者以root权限运行命令   
Sergiu Gatlan  代码卫士   2025-02-10 10:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**思科已发布多个补丁，修复位于ISE 安全策略管理平台中的两个严重漏洞。**  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMSWibWAtgdmXrjj5j2kEknv1Z2zibOSnkj9yKCicco1MTdzoHHoH2MmvgZy7lnbX0VMsia76lsCW34Mjg/640?wx_fmt=gif&from=appmsg "")  
  
  
企业管理员使用思科ISE作为身份和访问管理 (IAM) 解决方案，它将认证、授权和会计集成到一款设备中。这两个漏洞（CVE-2025-20124和CVE-2025-20125）可被具有只读管理员权限的认证远程攻击者利用，以root身份运行任意命令并绕过未修复设备上的授权。  
  
这些漏洞影响思科ISE和思科ISE-PIC设备，无论设备配置如何。思科提到CVE-2025-20124时提到，该漏洞的评分为9.9，“是因为受影响软件的用户所提供的Java字节流不安全的反序列化造成的。攻击者可通过向受影响API发送构造的序列化Java对象的方式，利用该漏洞。成功利用该漏洞可导致攻击者在设备上执行任意命令并提升权限。”  
  
CVE-2025-20125是因为特定API中缺乏授权和对用户提供数据的验证不当造成的。攻击者可通过使用恶意构造的HTTP请求利用这一漏洞获取信息、修改受影响系统的配置并重新加载设备。  
  
建议管理员尽快迁移或将ISE设备升级至如下已修复版本。  
<table><thead><tr><td valign="top" style="border-color: rgb(29, 54, 82);background: rgb(238, 238, 238);" width="234"><p style="text-align:center;"><span style="font-size: 15px;"><strong><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;">Cisco ISE </span></strong><strong><span style="color: rgb(51, 51, 51);font-family: 宋体;">软件发布</span></strong></span></p></td><td valign="top" style="border-top-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left: none;background: rgb(238, 238, 238);" width="224"><p style="text-align:center;"><span style="font-size: 15px;"><strong><span style="font-size: 15px;color: rgb(51, 51, 51);font-family: 宋体;">已修复版本</span></strong></span></p></td></tr></thead><tbody><tr><td valign="top" style="border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left-color: rgb(29, 54, 82);border-top: none;" width="234"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.0</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);" width="224"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: 宋体;font-size: 15px;">迁移至已修复版本</span></p></td></tr><tr><td valign="top" style="border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left-color: rgb(29, 54, 82);border-top: none;" width="234"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.1</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);" width="224"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.1P10</span></p></td></tr><tr><td valign="top" style="border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left-color: rgb(29, 54, 82);border-top: none;" width="234"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.2</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);" width="224"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.2P7</span></p></td></tr><tr><td valign="top" style="border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left-color: rgb(29, 54, 82);border-top: none;" width="234"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.3</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);" width="224"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.3P4</span></p></td></tr><tr><td valign="top" style="border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left-color: rgb(29, 54, 82);border-top: none;" width="234"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;font-size: 15px;">3.4</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);" width="224"><p style="text-align:left;"><span style="color: rgb(51, 51, 51);font-family: 宋体;font-size: 15px;">不受影响</span></p></td></tr></tbody></table>  
  
思科产品安全事件响应团队 (PSIRT) 尚未发布公开利用代码的证据或这两个严重漏洞已遭利用的证据。上周三，该公司还提醒注意影响 IOS、IOS XE、IOS XR (CVE-2025-20169、CVE-2025-20170、CVE-2025-20171)和NX-OS（CVE-2024-20397）软件的漏洞，它们可导致攻击者触发拒绝服务条件或绕过NX-OS镜像签名验证。  
  
思科尚未修复影响启用SNMP特性的IOS、IOS XE和IOS XR软件中的DoS 漏洞，不过表示该漏洞并未早在也利用，并发布了缓解措施称管理员应禁用易受攻击设备上的易受攻击对象标识符（不过这样做可影响网络功能或性能）。该公司计划推出在2月份和3月份推出软件更新，修复该SNMP DoS 漏洞。  
  
去年9月份，思科还修复了另外一个ISE漏洞，可导致攻击者在易受攻击设备上将权限提升至 root。两个月之后，它又修复了一个满分漏洞，可导致攻击者以root权限在易受攻击的 URWB 访问点上运行命令。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[思科提醒注意严重的DoS漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247522160&idx=1&sn=1b0f6777dc7235311e5c6a6e6f764ee7&scene=21#wechat_redirect)  
  
  
[引导加载程序存在高危漏洞，影响思科100多个交换机机型](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521713&idx=1&sn=7bdde63b35fa4a28908581f18c38883e&scene=21#wechat_redirect)  
  
  
[思科证实已存在10年的ASA产品漏洞正遭利用](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247521684&idx=2&sn=d7717056b8823ba4a6de5202613f9d39&scene=21#wechat_redirect)  
  
  
[思科ISE多个漏洞可用于一次点击exploit](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514814&idx=1&sn=4b21aca000d15beda25426bb096a28d7&scene=21#wechat_redirect)  
  
  
[思科ISE中存在HTML验证缺陷](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247485894&idx=5&sn=5d84f96178759fde36942686aaaa7dce&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
  
https://www.bleepingcomputer.com/news/security/critical-cisco-ise-bug-can-let-attackers-run-commands-as-root/  
  
  
题图：  
Pexels   
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
  
