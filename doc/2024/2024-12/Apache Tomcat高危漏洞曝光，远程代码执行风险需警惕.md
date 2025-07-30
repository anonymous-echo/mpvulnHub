#  ​Apache Tomcat高危漏洞曝光，远程代码执行风险需警惕   
看雪学苑  看雪学苑   2024-12-19 09:59  
  
近期，Apache Tomcat，这款广泛使用的开源Web服务器和servlet容器，被披露存在两个严重的安全漏洞。这些漏洞可能使攻击者远程执行代码，甚至引发服务拒绝攻击，对企业信息系统安全构成严重威胁。  
  
  
Apache软件基金会紧急发布了针对Apache Tomcat的补丁，以修复这两个被标识为CVE-2024-50379和CVE-2024-54677的漏洞，并强烈建议用户立即升级到最新版本以增强系统安全性。  
  
  
CVE-2024-50379是一个“重要”级别的漏洞，影响了多个版本的Apache Tomcat，包括11.0.0-M1至11.0.1、10.1.0-M1至10.1.33以及9.0.0.M1至9.0.97。该漏洞允许在特定条件下远程代码执行，攻击者可以利用并发读取和上传操作中的竞态条件，如果默认的servlet配置了写权限，且文件系统不区分大小写，攻击者就能上传文件并使其被错误地当作JSP文件执行。  
  
  
另一个被分类为“低”级别的CVE-2024-54677漏洞，虽然看似威胁不大，但同样不容忽视。它影响了相同版本的Apache Tomcat，由于Tomcat提供的示例Web应用程序未能限制上传数据的大小，攻击者可以通过上传大量数据触发内存溢出错误，导致服务拒绝。  
  
  
值得注意的是，默认情况下，示例Web应用程序仅允许从本地主机访问，这在一定程度上限制了潜在的攻击范围。然而，安全研究人员Elysee Franchuk、Nacl、WHOAMI、Yemoli和Ruozhi以及Tomcat安全团队发现的这些漏洞，提醒我们必须重视定期的安全审计和及时的补丁更新。  
  
  
  
  
资讯来源：  
cybersecuritynews  
  
转载请注明出处和本文链接  
  
  
  
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
  
