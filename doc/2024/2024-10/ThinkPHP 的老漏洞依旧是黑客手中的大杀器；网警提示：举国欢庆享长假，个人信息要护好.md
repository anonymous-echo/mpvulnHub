#  ThinkPHP 的老漏洞依旧是黑客手中的大杀器；|网警提示：举国欢庆享长假，个人信息要护好   
 黑白之道   2024-10-05 10:36  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
  
**ThinkPHP 的老漏洞依旧是黑客手中的大杀器；**  
  
研究人员发现安全领域出现了令人不安的趋势：  
攻击者不仅对新披露的漏洞十分感兴趣，对已知的漏洞也丝毫不放过，尽管有些漏洞已经存在了好些年头，攻击者仍然能够通过老漏洞成功完成攻击。  
  
典型的例子就是 ThinkPHP 远程代码执行漏洞 CVE-2018-20062 和 CVE-2019-9082，距今已有六年的时间了，攻击者仍然在使用这些漏洞进行攻击。  
  
研究人员最早在 2023 年 10 月 17 日首次检测到此类攻击，与传统意义上的 POC 不同，攻击者会从控制的 C&C 服务器下载经过混淆的 Shell 脚本。虽然仅仅持续了几天小范围的攻击就销声匿迹，但 2024 年 4 月攻击死灰复燃且规模比之前大得多。  
##   
  
**ThinkPHP**  
  
  
## ThinkPHP 是中文社区开源的 Web 应用框架，主要用于开发基于 PHP 的 Web 应用。该框架提供了一组库、组件和工具，通过 MVC 架构简化 Web 应用的构建过程。  
  
CVE-2018-20062 与 CVE-2019-9082 是在 ThinkPHP 旧版本中发现的漏洞，不仅是影响 ThinkPHP 还有基于 ThinkPHP 二次开发的 CMS，如 NoneCMS 与 open-source BMS。这两个漏洞都可以让攻击者可以在失陷主机上远程执行代码，从 2018 年被披露已经长达六年。  
  
  
**在野攻击**  
  
  
## 研究人员发现中国境内的失陷主机在尝试下载名为 public.txt 的文件，恶意文件将以 roeter.php 为名保存在是失陷主机中。从名称上来看，应该是 router 单词拼写错了。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGu9iaGHxmvgsvyFa16waich6gibw2EdYyBiaHzk4ZibWJXS8duVzLEVibTqLQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
在野攻击  
  
  
下载的文件包含一个经过混淆的 WebShell 脚本，该脚本使用 ROT13 算法进行混淆。尽管攻击者通过很长的十六进制字符串进行混淆，但却选择了非常简单的密码（admin）作为 WebShell 的密码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGgPHic1Vr3jMekHp4uOVJ4QDwsiacicFI1oc5xFaiaAbkcnpKjL6EQHEraw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
混淆的 WebShell  
  
  
攻击从 Zenlayer 云提供商（ASN 21859）的 IP 地址发起，这些服务器主要位于中国香港。分析人员对部署后门的服务器进行了检查，发现该服务器也感染了相同的 WebShell。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hG7lezBu6JEJQ3h29Qd1iafHZh6rjIf9j4CnvjFNvCvy8triaVlSyRF0Zw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
失陷主机被用作分发服务器  
  
  
这表明该服务器很可能是攻击基础设施中的一个节点，攻击者通过这种方式来降低运营成本。并且这样也可以让执法部门更难以关停服务器，运营商不会轻易关闭有合法服务的服务器。  
  
  
**Dama WebShell**  
  
  
## 该 WebShell 具备浏览文件系统、修改文件时间戳等高级功能，攻击者借此实现混淆的功能。东欧和西欧的网络犯罪分子经常使用英文 WebShell（如 WSO-GN WebShell），但 Dama WebShell 的界面语言是繁体中文。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGU0Qth3g52IvB3arjkThbs8wUR9u8WpaMorVVM9KMkN0Rpgpkeic7nxA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
用户界面  
  
  
该 WebShell 可以将文件上传到服务器来收集核心的系统数据，如操作系统版本与 PHP 信息，这可以帮助攻击者实施提权漏洞攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icaqFo7ZajeZ5LicFLVX35hGluShQmicGKlMbRSia8qwqCEcqkrw8MicQpBaJVzo74GiaEPiaPhiaI2sg1AQ/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
与数据库进行交互  
  
  
攻击者会利用包括端口扫描等功能对数据库和服务器上的数据进行访问。Dama WebShell 还提供了多种提权方法，如绕过已被禁用的敏感 PHP 函数进行沙盒逃逸最终执行 Shell 命令。  
  
Dama WebShell 还可以利用 Windows 任务调度功能配置 WMI 添加高权限用户。尽管配备了用于直接解释执行代码的 PHP 解释器，但 Dama WebShell 并不支持通过命令行执行系统命令。  
##   
  
**总结**  
  
  
##   
  
尽管攻击者已经了解这些漏洞很久很久，但仍然在继续使用并且能够攻击成功。这凸显了组织在识别易受攻击资产和升级补丁管理上，持续面临巨大挑战。  
  
研究人员发现并非所有的受害者都使用了 ThinkPHP，攻击者可能不加区分进行了广泛的攻击。攻击者一方面对恶意脚本进行了混淆处理，另一方面也有很低级技术的表现，这二者十分割裂。当然，攻击技术先进并不代表着背后的攻击者也很熟练。  
# 网警提示：举国欢庆享长假，个人信息要护好  
  
国庆小长假来啦  
  
你是不是已经做好攻略了呀？  
  
但是，防骗攻略你做好了嘛？  
  
你的个人信息保护好了嘛？  
  
你放假了，  
  
骗子可不会放假哦！  
  
很多的诈骗都是  
  
从你的个人信息泄露开始的！  
  
网安蜀黍为您准备了一份  
  
个人信息保护大礼包  
  
快来查收吧！  
  
  
**骗局一：**  
****  
**虚假网站**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5uDcC8qxBccibKNXtXsdGjFfmfM0ib9fOR1TwyicQ7UDibRVj0jGpFjomYre787hHqLbwStdeQpdiaFZmy5aIaxP7NQ/640?from=appmsg&tp=wxpic&wxfrom=13&wx_lazy=1&wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ukDZVmfjnPRJJD4a7RKcqJPYkicQTlnpgQUKOQQID3IZGibib3MvNiaojabFrCF6OIKRQicqicANpW6HxhIwYJxySaiaQ/640?from=appmsg&tp=wxpic&wxfrom=13&wx_lazy=1&wx_co=1&wx_fmt=jpeg "")  
  
  
假期很多人会选择网上冲浪，  
  
网络钓鱼网站也开始蠢蠢欲动，  
  
您一旦点击钓鱼网站链接，  
  
很有可能感染病毒，  
  
进而网上银行账户、密码、  
  
个人信息等  
  
或将面临被盗危险。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J3ZDGMAH6vbUsqibdWZJAaiaT0KkoFZjWYiapllnkqUtePISWUXWEl5DGP5YI8icFkzY9fOib8x4bhy1iaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**警方提示**  
  
   建议广大网民在有认证标识的官方网站或APP上网冲浪，切勿点击未认证的网站链接。  
  
**骗局二：****免费WIFI**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5uDcC8qxBccibKNXtXsdGjFfmfM0ib9fOR1TwyicQ7UDibRVj0jGpFjomYre787hHqLbwStdeQpdiaFZmy5aIaxP7NQ/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_fmt=gif&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ukDZVmfjnPRJJD4a7RKcqJPYkicQTlnpgmaRhp1wiau145aFOOpPrrz4iaXribzmCoOhTLYcSiaVLReMUpQ9vOTghBg/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=jpeg&tp=wxpic "")  
  
  
很多公共场所、景点等  
  
会向游客提供“免费”WiFi，  
  
如果连入“山寨”WiFi,  
  
那么您的个人信息、银行卡密码  
  
等可能会被泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J3ZDGMAH6vbUsqibdWZJAaiaT0KkoFZjWYiapllnkqUtePISWUXWEl5DGP5YI8icFkzY9fOib8x4bhy1iaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**警方提示**  
  
     
有的不法分子会在人群聚集场所、景点等地方设立免费无密码  
WiFi，名称与景点、商场等地方的几乎一致，一旦连接上这种山寨WiFi，不法分子就有可能获取您的个人信息、银行卡账号密码等，请大家一定要仔细辨别，必要时向工作人员求证。  
  
**骗局三：****机票退、改签**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5uDcC8qxBccibKNXtXsdGjFfmfM0ib9fOR1TwyicQ7UDibRVj0jGpFjomYre787hHqLbwStdeQpdiaFZmy5aIaxP7NQ/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_fmt=gif&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ukDZVmfjnPRJJD4a7RKcqJPYkicQTlnpgGkdMEa4S9a2LTcWLqLlzLuoOIbgBY3UtkJmbOqZTeg4mDibUX4iaxlqw/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=jpeg&tp=wxpic "")  
  
  
不法分子  
会以  
  
您的航班因天气等原因  
  
延误或者取消  
为由  
，  
  
引导  
您点击短信链接  
  
输入身份信息  
  
进行退、改签机票  
，  
  
导致个人信息泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J3ZDGMAH6vbUsqibdWZJAaiaT0KkoFZjWYiapllnkqUtePISWUXWEl5DGP5YI8icFkzY9fOib8x4bhy1iaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**警方提示**  
  
    遇到此类电话应该打电话到航空公司进行核实或到官方网站及APP里进行操作，请大家务必提高警惕，不要轻易相信陌生电话号码及短信链接。  
  
**骗局四：****超低价旅行团**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5uDcC8qxBccibKNXtXsdGjFfmfM0ib9fOR1TwyicQ7UDibRVj0jGpFjomYre787hHqLbwStdeQpdiaFZmy5aIaxP7NQ/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_fmt=gif&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ukDZVmfjnPRJJD4a7RKcqJPYkicQTlnpgia3Yt46PlLqqOH75LLQlnbMsVGnTxOySWFgSzoBcSmEUxf68KibicYCDg/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=png&tp=wxpic "")  
  
  
不法分子会以  
  
各种“免费”“超低价”的  
  
旅行优惠活动，  
  
引导您进入“活动”链接  
  
输入身份信息等，  
  
导致个人信息泄露。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J3ZDGMAH6vbUsqibdWZJAaiaT0KkoFZjWYiapllnkqUtePISWUXWEl5DGP5YI8icFkzY9fOib8x4bhy1iaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**警方提示**  
  
   切记天上不会掉馅饼，  
很多低价、免费的旅游服务产品都可能是骗子设立的陷阱，假期出行一定要选择正规的旅行社，不要轻易相信超低价的旅行项目  
。  
  
  
**骗局五：ETC认证**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/5uDcC8qxBccibKNXtXsdGjFfmfM0ib9fOR1TwyicQ7UDibRVj0jGpFjomYre787hHqLbwStdeQpdiaFZmy5aIaxP7NQ/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_fmt=gif&tp=wxpic "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/ukDZVmfjnPRJJD4a7RKcqJPYkicQTlnpgoDOia5JH4PvJnyvZQWyrPxO8vJShsI3zmfl9amlmkyXR1SPicS8xuTGA/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=jpeg&tp=wxpic "")  
  
  
不法分子声称  
  
 自己是ETC平台工作人员，  
  
 发现您的ETC认证失效，  
  
需要点击链接，  
  
填写个人信息重新进行认证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JaFvPvvA2J3ZDGMAH6vbUsqibdWZJAaiaT0KkoFZjWYiapllnkqUtePISWUXWEl5DGP5YI8icFkzY9fOib8x4bhy1iaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
**警方提示**  
  
    不法分子制作貌似“官方”的网站冒充正规的ETC平台，向车主发送“ETC过期认证、系统升级、卡被停用”等欺诈短信，并且附上假冒网站链接，若按照要求一步步操作，您的个人信息可能会被泄露，请大家一定要拨打官方电话进行询问，或者去线下营业厅进行咨询。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ukDZVmfjnPRJJD4a7RKcqJPYkicQTlnpguaYmDeGiasuHBcicSfSyn0uIodMok4ibdIb1tLBPsCtcTJGSjAX5lGKLQ/640?from=appmsg&wxfrom=5&wx_lazy=1&wx_fmt=gif&tp=wxpic "")  
  
网络给出行、生活  
  
带来便利的同时，  
  
也存在个人信息被泄漏的风险，  
  
请大家提高警惕，  
  
不要给骗子可乘之机！  
  
最后  
  
祝大家度过一个  
  
安全、愉快的国庆假期！  
  
> **文章来源 ：freebuf、山东网警**  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
  
