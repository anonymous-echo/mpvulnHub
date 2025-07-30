#  尽快更新！VMware修复严重远程代码执行漏洞   
看雪学苑  看雪学苑   2023-06-09 17:59  
  
虚拟化巨头VMware于6月9日新发布了多个安全补丁，以解决VMware Aria Operations for Networks中的三个严重漏洞——未经身份验证的攻击者可利用它来远程执行任意代码、访问敏感信息。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GibpU3NlYsY0CMsn93QviaFePRRtQGm0oqXnVs5F8wKeEicawzGY1uibP8HIvBYxvPJ6Btibyu2AZTebg/640?wx_fmt=png "")  
  
  
VMware Aria Operations for Networks是一个网络可见性和分析工具，以前被称为vRealize Network Insight（vRNI），它能够帮助管理员优化网络性能或管理扩展各种VMware和Kubernetes部署，以构建一个优化、高度可用且安全的网络基础设施。  
  
  
VMware修复的三个安全漏洞中最严重的是一个命令注入漏洞（CVE-2023-20887，CVSSv3评分9.8），能够被未经身份验证的攻击者在不需要用户交互的低复杂度攻击中利用。VMware表示：“具有VMware Aria Operations for Networks网络访问权限的恶意行为者可能能够执行命令注入攻击，从而导致远程代码执行。”   
  
  
利用VMware修复的第二个漏洞（CVE-2023-20888，CVSSv3评分9.1），假如攻击者拥有对目标设备的网络访问权限以及有效“成员”角色凭据，就有可能进行成功的反序列化攻击，从而导致远程代码执行。  
  
  
修复的最后一个漏洞是一个信息泄露漏洞（CVE-2023-20889，CVSSv3评分8.8），使恶意行为者可以在成功的命令注入攻击后访问敏感信息。  
  
  
据VMware官网公告，影响VMware Aria Operations Networks版本6.x的三个漏洞已在以下版本中得到修复：6.2、6.3、6.4、6.5.1、6.6、6.7、6.8、6.9和6.10。由于没有缓解措施，强烈建议受影响的用户及时下载修复补丁以防止受到攻击。  
  
  
详细操作步骤请参照VMware官网链接：https://kb.vmware.com/s/article/92684  
  
  
  
编辑：左右里  
  
资讯来源：VMware  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
注入  
  
Web安全头号大敌。攻击者把一些包含攻击代码当做命令或者查询语句发送给解释器，  
这些恶意数据可以欺骗解释器，从而执行计划外的命令或者未授权访问数据。  
  
注入攻击漏洞往往是应用程序缺少对输入进行安全性检查所引起的。注入漏洞通常能在  
SQL 查询、LDAP 查询、OS 命令、程序参数等中出现  
。  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8E9S6vNnUMRCOictT4PicNGMgHmsIkOvEno4oPVWrhwQCWNRTquZGs2ZLYic8IJTJBjxhWVoCa47V9Rw/640?wx_fmt=gif "")  
  
**球在看**  
  
****  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1UG7KPNHN8FxuBNT7e2ZEfQZgBuH2GkFjvK4tzErD5Q56kwaEL0N099icLfx1ZvVvqzcRG3oMtIXqUz5T9HYKicA/640?wx_fmt=gif "")  
  
戳  
“阅读原文  
”  
一起来充电吧！  
  
