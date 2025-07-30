#  韩国黑客利用 WPS Office 零日漏洞部署恶意软件   
ZIcheng  FreeBuf   2024-09-01 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
据BleepingComputer消息，与韩国有关的网络黑客组织 APT-C-60近期一直在利用 Windows 版 WPS Office 中的零日漏洞，针对东亚地区目标部署 SpyGlace 后门。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEc7Zy5pv47N1ibm82uWlkYW0DCULKfib807kyrx47GdSMasecXGcic7IVbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这个被跟踪为 CVE-2024-7262 的零日漏洞至少自 2024 年 2 月下旬以来就被用于野外攻击，影响了WPS 12.2.0.13110至12.1.0.16412之间的版本。今年3月，金山软件已经修补了该漏洞。  
  
  
CVE-2024-7262 存在于软件处理自定义协议处理程序的方式中，特别是 "ksoqing://"，允许通过文档中特制的 URL 执行外部应用程序。 由于对这些 URL 的验证和消毒不当，该漏洞允许攻击者制作恶意超链接，从而导致任意代码执行。  
  
  
APT-C-60 通过创建MHTML 文件，在其中嵌入了隐藏在诱饵图像下的恶意超链接，诱使受害者点击并触发漏洞。  
  
  
恶意URL 参数包括一个 base64 编码命令，用于执行一个特定插件 (promecefpluginhost.exe)，该插件会尝试加载包含攻击者代码的恶意 DLL (ksojscore.dll)，该 DLL 作为 APT-C-60 的下载器组件，用于从攻击者的服务器（一个名为 "SpyGlace "的自定义后门）获取最终有效载荷 (TaskControler.dll)。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39vt3r0UGG1tzwO3skkIoEc9lvskdbrjicm9QptXaTAQR4ibyU4fiaMN1QJhHjibjhRNUIuQicxvRYBtUA/640?wx_fmt=jpeg&from=appmsg "")  
  
APT-C-60攻击概述  
  
  
此外，研究人员还发现了另外一个任意代码执行漏洞 CVE-2024-7263，该漏洞出现于针对 CVE-2024-7262的补丁缺陷当中。具体来说，金山软件虽然增加了对特定参数的验证，但一些参数（如 "CefPluginPathU8"）仍未得到充分保护，从而允许攻击者再次通过promecefpluginhost.exe指向恶意DLL的路径。目前该漏洞也于今年5月得到了修补。  
  
  
由于这两个漏洞利用具有较高的欺骗性，能诱使任何用户点击看起来合法的电子表格，安全专家建议WPS用户尽快升级至12.2.0.17119以上或最新版本。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/apt-c-60-hackers-exploited-wps-office-zero-day-to-deploy-spyglace-malware/  
  
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494785&idx=1&sn=9fb76edd4009af6f5cfdf4c7fc19ae1b&chksm=ce1f161ef9689f0803457ac72b1337a2b371c4d53779f73d7ca5278ff497255a512e4f1ccf96&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494753&idx=1&sn=a9ee1d680adf601e9ee212fc3841387f&chksm=ce1f16fef9689fe8ad2926bc3739025b04955e5c29fee949f44be9fe8262d8723110eb50b6b9&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
