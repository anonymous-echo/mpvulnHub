#  真0day分享！用ZoomEye发现通用组件0day漏洞的新姿势！   
pbuff07  道一安全   2024-05-09 07:43  
  
免责声明  
  
  
  
道一安全（本公众号）的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！  
  
前言  
  
  
  
**本文转载于：增益安全**  
  
  
  
通过该方法，成功在短时间内使用ZoomEye挖掘到到多个通用应用的未公开高危漏洞。  
  
正常来说挖掘漏洞是通过审计代码或者黑盒审计发现漏洞，这是比较常规的办法，针对某个应用或者产品的功能点进行漏洞挖掘。  
  
转念一想是否有办法通过具体的漏洞信息去反推哪些站点或者应用存在此漏洞？当然是可以的，不过弊端就是挖掘的目标是随机的了，给这个技巧取名叫“目标反推法”。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARBrRUhno2znyibRPmicevJdLCRJjU5EOv3EHRdjNF4tlakPctmYg7ia97mPjUEoMO6WgCSjEmcQ31e0g/640?wx_fmt=png&from=appmsg "")  
  
实战挖掘  
  
  
  
按照目标反推法我举个例子并用ZoomEye进行实践漏洞挖掘，假设有个任意文件读取漏洞payload为down.php?Filename=xxxxxx（来源CVE数据库）。  
  
我们假定包含该关键字（down.php?Filename=）的站点或者应用都存在任意文件读取漏洞，使用ZoomEye对包含该关键字的页面进行测绘，共测绘出1302条结果。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubFKAyVkicuX9bbYAibiaFn05byD9VrncWMkZucSGaJiaDTOAmlb13e42ic2svyrcV0MkficohqZCBHQVLiaw/640?wx_fmt=png&from=appmsg "")  
  
一条一条的打开站点尝试Payload显然是个低级的做法，即使编写脚本验证但每个站点的页面情况都存在差异短且时间不容易全部兼容（当然也可借助三方提取工具）。  
  
简便的方法是在ZoomEye页面的点击右侧聚合结果中的Title（ZoomEye这个功能很赞！没有任何限制且可以按照多个字段自由聚合），通过查看网站Title的聚合结果可以快速查看哪些站点具有相同的标题名，往往通用组件一般都具有相同的网站名。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubFKAyVkicuX9bbYAibiaFn05byZ2MMdarqHuYtmibaNsz5BlFMNyBsnO92aaNOKwoXia3fhBG8ERzoylkw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubFKAyVkicuX9bbYAibiaFn05byB0U8DyhZ3R75ibSMlrfX4XoIdAOohdVDUJfvcTiaiaUvBZhMKYKAJn0Kg/640?wx_fmt=png&from=appmsg "")  
  
聚合数据显示了不同的标题对应的资产数量，我们以标题为”NES 웹하드”的应用为例展开说明】。  
  
点击对应的标题查看具体有哪些资产，并查看我们搜索的Payload在站点中具体的呈现方式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubFKAyVkicuX9bbYAibiaFn05byOpFh0ibXcVtRZL6p624MQc97NVIPH4vO5Avm9ib5DOkYMIia9Pia4kTiaPA/640?wx_fmt=png&from=appmsg "")  
  
复制带有Payload 关键词的地址并启用fuzz脚本（自己编写或后台回复fuzz获取）对下面的链接进行测试。  
  
http://xxx.xxx.xxx.xxx/control/data/file_down.php?filename=xxxxx  
  
很明显啊，不到3秒就完成了fuzz并确定了漏洞存在！挖掘一个通用组件的漏洞就是这么快，主要是思维方法要活跃。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GfgZiaPCOARBrRUhno2znyibRPmicevJdLCgqZSvbdSkgKTHfoGn9d9RRgMCJLSKcOv4qGiaLwQAAqAqvfyIpDaJ1Q/640?wx_fmt=png&from=appmsg "")  
  
总结  
  
  
  
**目标反推法挖掘漏洞的重点在于对漏洞出发点关键payload的收集与fuzz测试，可以参考CVE漏洞库中关于各类漏洞的介绍说明（其中会包含漏洞触发点）。**  
  
本文仅用任意文件下载的某个Payload作为该漏洞挖掘方法的说明，当然也可以用于到任意文件上传、SSRF、任意文件读取、XSS等多个漏洞的挖掘应用上，重点是要了解方法的本质和原理。  
  
致谢：  
  
**感谢CVND漏洞数据库提供的参考资料。******  
  
**感谢CVE漏洞数据库提供的参考资料。**********  
  
**大力致谢ZoomEye在探索过程中提供的帮助！**  
  
****  
**现在添加ZoomEye小助手进群即可获得2000积分！回复“增益安全”可再获取500积分！******  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GfgZiaPCOARBrRUhno2znyibRPmicevJdLC92TqBYhqHVdxCs4mo3w2NxKSaKR8vGPhw2lwAVbibYPDvrw9K9iaV0RQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
