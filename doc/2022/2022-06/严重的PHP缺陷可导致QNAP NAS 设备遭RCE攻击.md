#  严重的PHP缺陷可导致QNAP NAS 设备遭RCE攻击   
Sergiu Gatlan  代码卫士   2022-06-23 18:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
**编译：代码卫士**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRTWwlpMCsdOcEFxPE5lpiac6CyicibeHLjIfr95bCib4XZibnsYEpGBWXwUJCS7CuImpmD7PezsibCiarIQ/640?wx_fmt=png "")  
  
QNAP提醒客户称，攻击者可利用一个已存在三年的严重PHP漏洞 (CVE-2019-11043)，在NAS设备执行远程代码。该公司在最新发布的安全公告中表示，默认配置的NAS设备不受影响，运行老旧系统（在2017年至2019年期间发布）的设备受影响。  
  
  
  
QNAP 在安全公告中支持，“PHP 低于7.1.33的版本7.1.x、低于7.2.24的版本7.2.x以及低于7.2.11的7.3.x受一个漏洞影响，该漏洞如被利用可导致攻击者执行远程代码。为了保护您的设备，建议将系统定期更新至最新版本。”  
  
QNAP 是中国台湾的一家硬件厂商，已修复易受攻击的某些操作系统版本（QTS 5.0.1.2034 build 20220515 或后续版本以及QuTS hero h5.0.0.2069 build 20220614 或后续版本）。  
  
该漏洞是CVE-2019-11043，影响运行如下系统的大量设备：  
  
- QTS 5.0.x 及后续版本  
  
- QTS 4.5.x 及后续版本  
  
- QuTS hero h5.0.x 及后续版本  
  
- QuTS hero h4.5.x 及后续版本  
  
- QuTScloud c5.0.x 及后续版本  
  
  
  
QMAP 客户如需将NAS设备自动更新至最新的固件版本，则需要以管理员身份登录 QTS、QuTS hero 或 QuTScloud，点击控制面板＞系统＞固件更新下的“检查更新”按钮。另外也可从Support＞Download Center下载 QNAP 网站更新，手动升级设备。  
  
  
**QNAP 设备遭勒索软件攻击**  
  
  
  
周四，QNAP提醒客户称注意设备遭部署DeadBolt 勒索软件payload的活跃攻击。  
  
上周末，Bleeping Computer 报道称，该勒索软件开始再次攻击易受攻击的QNAP NAS 设备。目前，QNAP 并未发布关于攻击的更多详情，因此无法获得关于这些新的 DeadBolt 和勒索活动中使用的感染向量。  
  
QNAP 正在开始着手在所有易受攻击固件版本中修复该PHP漏洞 (CVE-2019-11043)，用户应确保设备未暴露在互联网以阻止遭攻击。QNAP 指出，NAS 设备暴露到互联网的用户应当采取如下措施防止遭远程访问：  
  
- 禁用路由器的Port Forwading（端口转发）功能：进入路由器的管理接口，检查虚拟服务器、NAT或端口转发设置，并禁用NAS管理服务端口（默认是端口8080和433）的端口转发设置。  
  
- 禁用QNAP NAS 的UPnP 功能：进入 QTS 目录的myQNAPcloud，点击“自动路由器配置”并取消勾选的“启用UPnP 端口转发”。  
  
  
  
QNAP 还详述了如何隐藏远程SSH 和 Telnet 连接，更改系统端口号码，更改设备密码，并启用IP和账户访问防护，进一步保护设备的安全。  
  
  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
开源卫士试用地址：  
https://oss.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[热门PyPI 包 “ctx” 和 PHP库 “phpass” 长时间未更新遭劫持，用于窃取AWS密钥](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511966&idx=1&sn=77856cc7ec3f5318efb4f18f2a8ddf66&chksm=ea949ef4dde317e2a06b85bfc4ca7d162951708a197fc45a2b94119ddf30e4457c29386705b2&scene=21#wechat_redirect)  
  
  
[PHP包管理器PEAR 中爆多个缺陷可发动供应链攻击，已潜伏15年](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247511248&idx=1&sn=87c97b4011784f136a91cb153c751622&chksm=ea949dbadde314ac482120774c44f03d2dc955e64635389f27d19a6f3e8cb1b786d5298889b8&scene=21#wechat_redirect)  
  
  
[PHP修复输入验证代码中的漏洞](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510661&idx=1&sn=882fe4f483a2808b85d16e7372a34df1&chksm=ea949befdde312f97669bf5ef1e1a90ed95cec1bde3fdea1c1276cfd6fa3420696d4e583bc96&scene=21#wechat_redirect)  
  
  
[漏洞10年深藏不露，PHP 项目依赖关系管理工具Composer安全吗？](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247507979&idx=1&sn=508b37a9d998ac15afbb21e518be42ad&chksm=ea949161dde3187794a482fcdd729f2355d3424db569f2f191e31ff35716644838059a65adb6&scene=21#wechat_redirect)  
  
  
[PHP Everywhere 插件中存在严重RCE，影响数千个 WordPress 站点](http://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247510489&idx=3&sn=e7dbd1c73e937e2dbf783f1afa6342e0&chksm=ea9498b3dde311a55ff3cf2243b100fde04a60f7793ad2161b221fe028886010921f3971eb0c&scene=21#wechat_redirect)  
  
  
  
  
  
**原文链接**  
  
https://www.bleepingcomputer.com/news/security/critical-php-flaw-exposes-qnap-nas-devices-to-rce-attacks/  
  
  
题图：  
Pixab  
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
  
