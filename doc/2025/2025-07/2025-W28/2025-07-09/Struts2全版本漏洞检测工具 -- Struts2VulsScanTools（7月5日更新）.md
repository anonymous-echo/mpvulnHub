> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MDQ5MjY1Mg==&mid=2247516963&idx=1&sn=ee00aff35e8bf7a7f1ded9b69d562f9e

#  Struts2全版本漏洞检测工具 -- Struts2VulsScanTools（7月5日更新）  
abc123info  Web安全工具库   2025-07-09 01:49  
  
资料合集  
  
链接：https://pan.quark.cn/s/770d9387db5f  
  
===================================  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，  
安全性自测  
，  
大家都要把工具当做病毒对待，在虚拟机运行。  
如有侵权请联系删除。个人微信：  
ivu123ivu  
  
  
**0x01 工具介绍**  
  
Struts2全版本漏洞检测工具。  
  
**0x02 安装与使用**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibtabJ2oOTUu6CGKaXeNOyPYxehR2hiaibpaPXbAAGw77eibGGW5rGvurKaycRIDxxiamQia3KMv4MIuhibQ/640?wx_fmt=png&from=appmsg "")  
  
1、点击“检测漏洞”，会自动检测该URL是否存在S2-001、S2-005、S2-009、S2-013、S2-016、S2-019、S2-020/021、S2-032、S2-037、DevMode、S2-045/046、S2-052、S2-048、S2-053、S2-057、S2-061、S2相关log4j2十余种漏洞。  
  
2、“批量验证”，（为防止批量geshell，此功能已经删除，并不再开发）。  
  
3、S2-020、S2-021仅提供漏洞扫描功能，因漏洞利用exp很大几率造成网站访问异常，本程序暂不提供。  
  
4、对于需要登录的页面，请勾选“设置全局Cookie值”，并填好相应的Cookie，程序每次发包都会带上Cookie。  
  
5、作者对不同的struts2漏洞测试语句做了大量修改，执行命令、上传功能已经能通用。  
  
6、支持GET、POST、UPLOAD三种请求方法，您可以自由选择。（UPLOAD为Multi-Part方式提交）  
  
7、部分漏洞测试支持UTF-8、GB2312、GBK编码转换。  
  
8、每次操作都启用一个线程，防止界面卡死。  
  
警告：该工具为漏洞自查工具，仅用来扫描及验证网站存在的Struts2漏洞，并可以协助管理员修复网站漏洞，也可用作授权的渗透测试，但严禁用于非授权的渗透测试、严禁用于攻击他人网站、严禁用于非法途径，否则后果自负。  
<table><tbody><tr><td data-colwidth="287"><section><span leaf=""><img class="rich_pages wxw-img" data-imgfileid="100022930" data-ratio="1.2452830188679245" data-s="300,640" data-src="https://mmbiz.qpic.cn/mmbiz_jpg/8H1dCzib3Uibu7uX2oYjbbibndft14nzUMIoRia7UqCAgMXSZAu1iaBDWSWLLuFnyibwfOiaCLO7YXaC6qib8icgHXwoe3Q/640?wx_fmt=jpeg" data-type="jpeg" data-w="1060" style="width:291px;height:362px;" type="block"/></span></section></td><td data-colwidth="287"><section><span leaf=""><img class="rich_pages wxw-img" data-imgfileid="100033312" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_jpg/8H1dCzib3UibtabJ2oOTUu6CGKaXeNOyPYMM1xlib25mGGypPK83X6qicEpVPWsmoRnicK1XXEFx7OplfdgYVey7Dng/640?wx_fmt=jpeg&amp;from=appmsg" data-type="jpeg" style="width:232px;height:325px;" type="inline"/></span></section></td></tr></tbody></table>  
  
****  
  
  
**·****今 日 推 荐**  
**·**  
  
  
> 本书系统介绍程序设计中各种常用的基础算法及典型案例，包括排序算法、递归算法、数论基础、组合数学基础、贪心算法、分治算法、动态规划算法和回溯算法等内容。 全书以图文并茂的方式讲解各基础算法的分析过程，侧重基础算法的深入理解与实践，配有大量图表辅助算法的分析过程，适用于有一定程序设计基础、尚未学习数据结构且对算法分析与设计感兴趣的算法初学者。   
  
  
  
  
