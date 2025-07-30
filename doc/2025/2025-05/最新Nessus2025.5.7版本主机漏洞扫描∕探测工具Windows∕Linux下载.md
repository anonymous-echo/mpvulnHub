#  最新Nessus2025.5.7版本主机漏洞扫描/探测工具Windows/Linux下载   
原创 城北  渗透安全HackTwo   2025-05-06 16:02  
  
前言  
  
现在只对常读和星标的公众号才展示大图推送 建议大家把  
**渗透安全HackTwo**  
"**设为星标⭐️**  
"  
**否则可能就看不到了啦！**  
****> Nessus号称是世界上最流行的漏洞扫描程序，全世界有超过75000个组织在使用它。该工具提供完整的电脑漏洞扫描服务，并随时更新其漏洞数据库。Nessus不同于传统的漏洞扫描软件，Nessus可同时在本机或远端上遥控，进行系统的漏洞分析扫描。对应渗透测试人员来说，Nessus是必不可少的工具之一。所以，本章将介绍Nessus工具的基础知识。  
  
  
**功能介绍：**  
  
nessus最新版通过修补系统中发现的漏洞，从而有效保护您的系统安全。  
  
nessus最新版高速洞发现,以确定哪些主朷正在运行哪些服务。  
  
无代理审核,以确保网络上没有主机丢失安全补丁。  
  
合规性检查,以验证网络上的每个主机都遵守您的安全策略。  
  
扫描计划以您选择的频率自动运行扫描。  
  
它的集成技术可帮助您执行物理和虚拟设备发现以及软件审核。  
  
此外，Nessus还对移动设备进行审核，以提供广泛的资产覆盖范围和整个组织环境的概况，包括电缆相关的硬件和支持无线的硬件。  
  
现在，您可以放心，您拥有一个用于检测可疑行为或已知恶意软件(例如僵尸网络)的应用程序。  
  
总而言之，Nessus通过提供针对潜在漏洞的解决方案，对其进行分类，对它们进行优先级排序，同时还执行非侵入性敏感内容审核，以更好地管理和更快地修补最重要的问题，从而为您的网络增加了几层保护。  
  
  
**软件特色：**  
  
最新的安全漏洞数据库，全面分析您的安全级别 我们主要专注于开发针对最新安全漏洞的安全检查。我们的安全检查数据库每天都会更新，所有最新的安全检查都在这里可用，可以使用nessus-update-plugins命令进行检索。所有最新安全检查的RSS提要都允许您监视添加了哪些插件以及何时添加。  
  
远程和本地安全性  
  
传统的网络安全扫描程序趋向于只关注网络上侦听的服务。现在，由于邮件客户端或Web浏览器中的漏洞，病毒和蠕虫正在传播，这种安全概念已过时。  
  
极具扩展性  
  
Nessus的构建使其可以轻松地将内存不足的单个CPU计算机扩展为具有千兆字节RAM的四CPU怪物。您为Nessus提供的功能越多，扫描网络的速度就越快。  
  
安全测试  
  
每个安全测试均以NASL形式编写为外部插件。这意味着更新Nessus不会涉及从Internet下载不受信任的二进制文件。每个NASL插件都可以读取和修改，以更好地了解Nessus报告的结果。  
  
多重服务  
  
如果主机运行同一服务两次或更多次，Nessus将测试所有这些服务。信不信由你，市场上一些扫描仪仍然认为主机只能一次运行一种服务器类型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq4sh5XrqxUp6OfQ61QGgH1qibXkvWIfmMBhjAVFEuxp7zNn9r9cnmDfKNJC4BgvyzkYJ4RDY1RhiayA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
01  
  
# 更新介绍  
  
  
```
更新说明
插件库更新至20250506新版本
更新客户端到Nessus-10.8.4-x64
新增Linux版本一键安装教程
```  
  
  
  
03  
  
# 使用/安装方法  
  
  
安装方法  
```
Nessus破解&更新
1.停止服务
net stop "Tenable Nessus" 

2.powershell管理员输入命令
attrib -s -r -h "C:\ProgramData\Tenable\Nessus\nessus\plugins\*.*"
attrib -s -r -h "C:\ProgramData\Tenable\Nessus\nessus\plugin_feed_info.inc"

3.把破解补丁⽂件复制粘贴到以下⽬录（如果没有该plugins⽂件夹则⼿动创建）
C:\ProgramData\Tenable\Nessus\nessus\plugin_feed_info.inc
C:\ProgramData\Tenable\Nessus\nessus\plugins\plugin_feed_info.inc
或者 
copy "C:\Users\WuXiaoTEAM\Desktop\plugin_feed_info.inc" "C:\ProgramData\Tenable\Nessus\nessus\plugin_feed_info.inc"
copy "C:\Users\WuXiaoTEAM\Desktop\plugin_feed_info.inc" "C:\ProgramData\Tenable\Nessus\nessus\plugins\plugin_feed_info.inc" 

4.再更新插件
"C:\Program Files\Tenable\Nessus\nessuscli.exe" update "C:\Users\wuxiao\Desktop\all-2.0_202204071544.tar.gz"

5.更改以下三个⽂件属性
attrib +s +r +h "C:\ProgramData\Tenable\Nessus\nessus\plugins\*.*"
attrib +s +r +h "C:\ProgramData\Tenable\Nessus\nessus\plugin_feed_info.inc"
attrib -s -r -h "C:\ProgramData\Tenable\Nessus\nessus\plugins\plugin_feed_info.inc"
```  
  
**详细安装看文件中的PDF**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq56zDE81McCiczOaMcbzd29aECpR4iaNJrlD3otnDqFhKyBUo7tXvahbt9YkiatUH8mArQpdTU0N6GXA/640?wx_fmt=png&from=appmsg "")  
  
**内置一键更新安装脚本**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq66Je6a8zFEOsaH9bXUvvyJxgibAiaE1wgP80ISEduglqksBMtxjIvDzz2Xeia3HSyRKH9tPmCaAGM0Q/640?wx_fmt=png&from=appmsg "")  
  
**Windows安装完成界面**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7qYlT7jN0VHX2nhf09BKibenXicvfmNR8q5vaSo4V3flFHbib1MTiay594vbaYQW4pjRnKlibn1D0mFLg/640?wx_fmt=png&from=appmsg "")  
  
**ubuntu安装完成界面**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6j8vDJ8ibqa8687SycmCiaIlcuM43MT2nmyfqav5nicDicLOF9qN1oicbHr7pkYfV5l0j950gOSZIHzFw/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
04  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250507获取软件**  
  
**👉点击加入-->>内部VIP知识星球享受VIP资源及工具！**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq5NaMqURKkJKlqib7xicGoduTrWthy1BWWXAypc8LnNib4tN7beJc7TuODicG4bOU79umBIzYFZZXt0icQ/640?wx_fmt=png "")  
****  
  
# 最后必看  
  
  
本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。  
  
  
为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。  
  
  
在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。  
  
  
如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
  
  
本工具来源于网络，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束，如有侵权请联系作者删除。  
  
  
  
  
# 往期推荐  
  
  
**1. 内部VIP星球福利介绍V1.4版本0day推送**  
  
**2. 最新BurpSuite2024.11.2专业（稳定版）**  
  
**3. 最新Invicti-Professional WEB漏洞扫描器更新**  
  
**4. 最新AWVS/Acunetix Premium漏洞扫描器下载**  
  
**5. 兔盾合规自评工具V1.1.3下载|等保测评**  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
关注回复星球 可加入知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜欢的朋友可以点赞转发  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/tqRiaNianNl1mGavBwp9Mf5RO17Jib6HN2NRSYwVT0jk8EzYYGOCRUxicpRHooD7KBlfkawia1zgicxnwMXlqxhFowCpwANhQJxA6A/640 "")  
  
  
