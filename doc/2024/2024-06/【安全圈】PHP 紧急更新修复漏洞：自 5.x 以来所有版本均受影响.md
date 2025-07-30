#  【安全圈】PHP 紧急更新修复漏洞：自 5.x 以来所有版本均受影响   
 安全圈   2024-06-09 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
PHP 项目维护团队昨日发布新补丁，修复了存在于 PHP for Windows 中的远程代码执行（RCE）漏洞，**并敦促用户尽快更新至 6 月 6 日发布的 8.3.8、8.2.20 以及 8.1.29 版本。**  
  
PHP 是一种广泛使用的开放源码脚本语言，设计用于网络开发，通常在 Windows 和 Linux 服务器上使用。  
  
Devcore 首席安全研究员 Orange Tsai 于 2024 年 5 月 7 日发现了这个新的 RCE 漏洞，并将其报告给了 PHP 开发人员。  
  
IT 之家注：该漏洞追踪编号为 CVE-2024-4577，影响到自 5.x 版以来的所有版本，可能对全球大量服务器造成影响。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg3m98iaL6LEGIc2FpQUD2dib72QabMW2epGV8p51gczAamQJDm8smom4UyDniaia5opZExbZtEg7UXJQ/640?wx_fmt=jpeg&from=appmsg "")  
  
此外 Shadowserver 基金会发布公告，表示已经检测到有黑客正扫描存在该漏洞的服务器。  
  
ITCVE-2024-4577 漏洞是由于处理字符编码转换时的疏忽造成的，在 Windows 上以 CGI 模式使用 PHP，尤其是使用 "Best-Fit" 功能的服务器环境，比较容易遭到黑客攻击。  
  
DevCore 的咨询解释说：  
  
在实施 PHP 时，团队没有注意到在 Windows 操作系统内进行编码转换的 Best-Fit 功能。  
  
未经认证的攻击者利用该漏洞，通过特定字符序列绕过 CVE-2012-1823 先前的保护。通过参数注入攻击，可在远程 PHP 服务器上执行任意代码。  
  
分析人员解释说，即使 PHP 未配置为 CGI 模式，只要 PHP 可执行文件（如 php.exe 或 php-cgi.exe）位于网络服务器可访问的目录中，CVE-2024-4577 仍有可能被利用。  
  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】安徽某单位被黑客袭击致3.54亿条信息泄露！公安机关联手检察院力挽狂澜](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061357&idx=1&sn=b19265ff01900d0995124e0a881cf86e&chksm=f36e12edc4199bfbbf18c0701b5eff8ccfa7d94f91f575d213cf26fa9f623747bab479e87b22&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg3m98iaL6LEGIc2FpQUD2dibjqnDmvVdzXOcpZ7KqHibXnpJR2aRrHoAuW3koibEPicwER1UhJ2IaPomQ/640?wx_fmt=jpeg "")  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=4&sn=f2d8dc93a6155a2a92a8db3148b35d5b&chksm=f36e1140c4199856cfdf7f6fe9794fdcf8c26069bf14ff1852b6b70a22ccbb9c5ea601a621df&scene=21#wechat_redirect)  
[【安全圈】TikTok零日漏洞被利用，可一键劫持高级账户](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061357&idx=2&sn=f47b137a7644573cda57047d5adbcb58&chksm=f36e12edc4199bfbd2049e0a1247b0a3abe21793a69df98b86667bc42b9b3befa06edf43b38a&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylj6K0SURKDqKLdrGonOyfuv7MpY3ZHmqM2ticPssTqXoNoAqx3glZVGIROhpHjFShvFibaWkxODibxhw/640?wx_fmt=jpeg&from=appmsg "")  
[【安全圈】加拿大省政府22个收件箱遭黑客入侵，疑似背后有国家支持](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061357&idx=3&sn=4441adf956b38987fcf055ff0d57061b&chksm=f36e12edc4199bfbd90b80236dbd9ddb32c1da03afeed5586efbc6b3ac1fbc4636bcb101e2e8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylj6K0SURKDqKLdrGonOyfuvlibuHfp4YvlLxy5awSLP3ZrA2QLl26QibRWiaRlnvMjdTPKK1ENZzLibFg/640?wx_fmt=png "")  
[](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652060928&idx=4&sn=f2d8dc93a6155a2a92a8db3148b35d5b&chksm=f36e1140c4199856cfdf7f6fe9794fdcf8c26069bf14ff1852b6b70a22ccbb9c5ea601a621df&scene=21#wechat_redirect)  
[【安全圈】马来西亚铁路资产公司 RAC 面临数据泄露指控](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061357&idx=4&sn=68cbed6724016a7dd32dde7d9b8cc792&chksm=f36e12edc4199bfb4f9938ec56ad87a76037a4d7ea9ccb54cd860b3b9b048a58716e6c55b21f&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
  
