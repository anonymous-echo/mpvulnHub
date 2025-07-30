#  VMware 修复CVSS评分9.8的身份验证绕过漏洞   
看雪学苑  看雪学苑   2022-08-03 17:58  
  
8  
月  
2  
日，虚拟化和云计算巨头  
VMware  
发布了一项重要的安全公告  
VMSA-2022-00  
21  
，通告用户修复数个在  
VMware产品中发现的安全漏洞。  
  
  
这些漏洞包括身份验证绕过、远程代码执行和权限提升。身份验证绕过漏洞意味着具有Workspace ONE Access、VMware Identity Manager 和 vRealize Automation网络访问权限的攻击者可以获得管理员访问权限；远程代码执行 （RCE）漏洞意味着攻击者可以诱使组件执行未经授权的命令；权限提升漏洞意味着具有本地访问权限的攻击者可以成为虚拟设备上的 root 用户。  
  
  
其中的一个身份验证绕过漏洞（CVE-2022-31656）是本次修复的最为严重的漏洞，CVSS v3基本得分为9.8/10。该漏洞由VNG Security的Petrus Viet报告，他发现该漏洞会影响VMware Workspace ONE Access、Identity Manager和vRealize Automation。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8GHY6YqkqNrVDDwnUD84eyjLlCPiacFTBpjct1FzLHiadORt7IlehQS3wcHcicjuQVEOR3MgsOPfSspg/640?wx_fmt=png "")  
  
  
此外，VMware 还修复了以下安全漏洞：  
  
CVE-2022-31657 – URL 注入漏洞  
  
CVE-2022-31658 – JDBC 注入远程代码执行漏洞  
  
CVE-2022-31659 – SQL 注入远程代码执行漏洞  
  
CVE-2022-31660 – 本地权限提升漏洞  
  
CVE-2022-31661 – 本地权限提升漏洞  
  
CVE-2022-31662 – 路径遍历漏洞  
  
CVE-2022-31663 – 跨站脚本（XSS）漏洞  
  
CVE-2022-31664 – 本地权限提升漏洞  
  
CVE-2022-31665 – JDBC 注入远程代码执行漏洞  
  
  
上述问题会影响以下产品：  
  
VMware Workspace ONE Access (Access)  
  
VMware Workspace ONE Access Connector
(Access Connector)  
  
VMware Identity Manager (vIDM)  
  
VMware Identity Manager Connector (vIDM
Connector)  
  
VMware vRealize Automation (vRA)  
  
VMware Cloud Foundation  
  
vRealize Suite Lifecycle Manager  
  
  
据VMware所说，目前没有证据表明CVE-2022-31656身份验证绕过漏洞在攻击中被利用。但VMware表示尽快采取措施在本地部署中修补或缓解这些问题非常重要，受影响的用户最好尽快安装 VMware 安全通报中列出的修补程序：  
  
https://kb.vmware.com/s/article/89096  
  
  
  
编辑：左右里  
  
资讯来源：VMware  
  
转载请注明出处和本文链接  
  
  
  
**每日涨知识**  
  
路由劫持  
  
通过欺骗方式更改路由信息，导致用户无法访问正确的目标，或导致用户的访问流量绕行黑客设定的路径，达到不正当的目的。  
  
  
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
