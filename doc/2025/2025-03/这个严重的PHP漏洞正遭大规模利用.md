#  这个严重的PHP漏洞正遭大规模利用   
Ionut Arghire  代码卫士   2025-03-11 18:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
****  
**威胁情报公司 GreyNoise 提到，威胁行动者们已开始大规模利用PHP中的一个严重漏洞CVE-2024-4577，它可导致攻击者在易受攻击服务器上实现远程代码执行。**  
  
  
该漏洞的CVSS评分为9.8，可在使用Apache 和 PHP-CGI 的Windows 服务器上遭利用，远程注入参数并执行任意代码，不过前提是这些服务器被设置为使用某些代码页面。  
  
由于PHP在Windows 中的视线并不考虑 “Best-Fit”行为，即将 Unicode 字符转换为最为接近的 ANSI 字符，因此攻击者可提供特定字符序列，当转换时可被 php-cgi 模块错误地解释为PHP选项。  
  
CVE-2024-4577首次在2024年6月公开披露，第一次利用尝试由勒索团伙在漏洞披露两天后实施。上周，思科提醒称，自2025年1月起，该漏洞就用于针对日本组织机构的恶意活动中，涵盖教育、娱乐、商业、技术和通信行业。在攻击中，攻击者执行多种工具获取系统权限、修改注册表密钥并添加调度任务实现持久性，并使用 Cobalt Strike 包 “TaoWu” 插件创建恶意服务。  
  
目前，GreyNoise 公司表示，对CVE-2024-4577的利用不仅限于日本。实际上令人注意的攻击也已发生在美国、英国、新加坡、印度尼西亚、印度、西班牙、马来西亚、中国台湾省等国家和地区。GreyNoise 公司提到，“GreyNoise 全球观测网络 (GOG) 是一款全球蜜罐网络，它已检测到单在2025年1月就检测到利用CVE-2024-4577的1089个唯一的IP。”该公司提醒称共有79个公开可用的利用。  
  
CVE-2024-4577影响Windows系统上的所有PHP版本，已在PHP版本8.1.29、8.2.20和8.3.8中修复。GreyNoise公司建议尽快更新至这些版本。  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[PHP中存在多个漏洞，速修复](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520981&idx=2&sn=804d3895d9a0ec8b221e9c44449e8673&scene=21#wechat_redirect)  
  
  
[骚操作：为了求职，劫持十几个热门 Packagist PHP 包](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247516377&idx=2&sn=0aa4f09f20d6e3b6f3d8c848b2feb158&scene=21#wechat_redirect)  
  
  
[热门开源Dompdf PHP 库中存在严重漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247515460&idx=2&sn=6ff90ed5a1a5cfe857a4aa75a16def08&scene=21#wechat_redirect)  
  
  
[PHP包管理器Composer组件 Packagist中存在漏洞，可导致软件供应链攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514137&idx=1&sn=347691413dc7ecfc2a2dedd365115329&scene=21#wechat_redirect)  
  
  
[严重的PHP缺陷可导致QNAP NAS 设备遭RCE攻击](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247512551&idx=2&sn=62ca391c055ea2839fe4178afcd48f4b&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.securityweek.com/mass-exploitation-of-critical-php-vulnerability-begins/  
  
  
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
  
