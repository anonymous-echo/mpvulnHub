#  【安全圈】Ghostscript 库中存在 RCE 漏洞，现已被积极利用   
 安全圈   2024-07-28 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
漏洞  
  
  
Linux 系统上广泛使用的 Ghostscript 文档转换工具包中存在一个远程代码执行漏洞，目前正在遭受攻击。  
  
Ghostscript 预装在许多 Linux 发行版上，并被各种文档转换软件使用，包括 ImageMagick、LibreOffice、GIMP、Inkscape、Scribus 和 CUPS 打印系统。  
  
此格式字符串漏洞的编号为 CVE-2024-29510，影响所有 Ghostscript 10.03.0 及更早版本。它使攻击者能够逃离 -dSAFER 沙盒（默认启用），因为未修补的 Ghostscript 版本无法在激活沙盒后阻止对 uniprint 设备参数字符串的更改。  
  
这种安全绕过尤其危险，因为它允许他们使用沙箱通常会阻止的 Ghostscript Postscript 解释器执行高风险操作，例如命令执行和文件 I/O。  
  
发现并报告此安全漏洞的 Codean Labs 安全研究人员警告称：" 此漏洞对提供文档转换和预览功能的 Web 应用程序和其他服务有重大影响，因为这些服务通常在后台使用 Ghostscript。"  
  
安全研究人员建议用户验证解决方案是否（间接）使用了 Ghostscript，如果是，请将其更新到最新版本。  
  
Codean Labs 还分享了 Postscript 文件，可以通过以下命令运行它来帮助防御者检测他们的系统是否容易受到 CVE-2023-36664 攻击：  
  
ghostscript   -q   -dNODISPLAY   -dBATCH   CVE-2024-29510_testkit.ps  
  
**在攻击中被积极利用**  
  
Ghostscript 开发团队在 5 月份修补了该安全漏洞，而 Codean Labs 则在两个月后发布了包含技术细节和概念验证漏洞代码的说明。攻击者已经在利用 CVE-2024-29510 Ghostscript 漏洞，使用伪装成 JPG（图像）文件的 EPS（PostScript）文件获取易受攻击系统的 shell 访问权限。  
  
开发人员警告称，如果生产服务中的任何地方有 ghostscript，则会受到令人震惊的远程 shell 执行攻击，应该升级它或将其从生产系统中删除。  
  
Codean Labs 补充道：" 针对此漏洞的最佳缓解措施是将 Ghostscript 安装更新至 v10.03.1。如果用户的发行版未提供最新的 Ghostscript 版本，则可能仍发布了包含此漏洞修复程序的补丁版本（例如，Debian、Ubuntu、Fedora）。"  
  
一年前，Ghostscript 开发人员修补了另一个严重的 RCE 漏洞 ( CVE-2023-36664 ) ，该漏洞也是由未修补的系统上打开恶意制作的文件引发的。  
  
END  
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhiajy13fWhusmOc6qpVeUzXpEIKJXgmDbcibpQichm7hVGIzU1dsYn1TiaOmJf1lBmgc9HpicyLl2MWLg/640?wx_fmt=jpeg "")  
[【安全圈】政务服务APP链接弹出色情网站？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063130&idx=1&sn=fa4e14ae88047daf9136a10416c5119d&chksm=f36e69dac419e0ccf4e6afed338d23e35d43a7e5a1bc65389944fa82ec5bcbb37bafb59967ac&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljRcwiceSEh8fJkzGq7XZ3aOTibd2adMe5ObYBWq0V72iciaib3ib9AmdEiawvRItlVyNWq2za4dJwpiaT28A/640?wx_fmt=png&from=appmsg "")  
[【安全圈】Patchwork黑客组织瞄准我国科技大学，窃取核心数据！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063130&idx=2&sn=ae42d5ef09b04de1ddcf3e4e3af18749&chksm=f36e69dac419e0cc245af966f6d17bf18667016426c1ab300fb00441338ccd6f391c08fe5781&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljRcwiceSEh8fJkzGq7XZ3aON30emLplAD03wDLmJofCbn9PBibX9ibFME37FSiaffV53SpWDMJicN9c7A/640?wx_fmt=png "")  
[【安全圈】广西一物业服务公司不履行个人信息保护义务被处罚](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063130&idx=3&sn=1235cc794cadb57e2b8b1d313d2dba08&chksm=f36e69dac419e0cce2627caa6d424c9d277f01fe599f7217e4f0e1b9b9090ebc3e975e9b7a05&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/INYsicz2qhvYTOYqHmmewiaoacNeb6icVfmKjQuX2Yh9WYFLicTneYU825BblkCYnflSBEEWrLy3NVyeElGGIVGRow/640?wx_fmt=other "")  
[【安全圈】美国政府最大IT服务商发生严重数据泄漏](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652063130&idx=4&sn=31a16a4f9f21004f5af0da5366307e59&chksm=f36e69dac419e0cce602c922a4b893def512649a5e5f97613908f04dee6a956709a1de4f6457&scene=21#wechat_redirect)  
  
  
  
  
  
  
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
  
