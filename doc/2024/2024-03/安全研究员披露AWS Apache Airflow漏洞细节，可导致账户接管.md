#  安全研究员披露AWS Apache Airflow漏洞细节，可导致账户接管   
看雪学苑  看雪学苑   2024-03-27 17:59  
  
上周四，Tenable Research的安全研究员发布了一篇博客文章，上面披露了亚马逊云服务（AWS）Apache Airflow的一个安全漏洞细节。这一漏洞可能被黑客利用来劫持受害者会话、实施远程代码执行攻击等。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8E77vMB76C9er64EUBOiaWKTAVVQVb58kibicXJsZVYE1LebJ819hNSzA7fyDWDshkWbnS4z1XYbDU0w/640?wx_fmt=png&from=appmsg "")  
  
  
  
这个漏洞名为“FlowFixation”，现已被AWS修复，由于这是一个云漏洞，不需用户另外采取任何措施。该漏洞存在于AWS工作流编排工具Managed Workflows for Apache Airflow (MWAA)中，漏洞源自AWS MWAA的Web管理面板上的会话固定、AWS服务器的错误配置，可能导致one-click会话劫持。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8E77vMB76C9er64EUBOiaWKTkSGvmVISDfCKib2riaowJXl3XGKd1Bqb12pYgxb7ibY6wNPf8FfuxDZxQ/640?wx_fmt=png&from=appmsg "")  
  
  
攻击者会先在自己的AWS服务器上托管恶意代码，然后诱使受害者访问自己的服务器，触发托管脚本将带有攻击者会话ID的cookie插入受害者的浏览器。以此获取到对受害者的网络面板的访问权限后，攻击者就能够查看潜在敏感的工作流数据，实施远程代码执行（RCE）攻击，并可能在其他服务之间实现横向移动。  
  
  
Tenable指出，共享架构（多个客户共享相同的父域名）容易被攻击者利用来执行同站攻击、Cookie Tossing，而这种风险可以通过简单的防护措施——公共后缀列表（Publix Suffix List，PSL)来减轻。PSL是由Mozilla建立并维护的社区倡议，通过阻止共享相同后缀子域的Cookie，可使注册在其中的域名避免同站攻击风险。  
  
  
Tenable发现，多个AWS、Azure和GCP域名未注册在PSL中，于是便向亚马逊、微软和谷歌报告了这一问题及其风险。AWS和Azure已经通过将错误配置的域名添加到PSL来解决这一问题，Google Cloud则表示该问题未严重到需要修复。  
  
  
  
编辑：左右里  
  
资讯来源：tenable、scmagazine  
  
转载请注明出处和本文链接  
  
  
**每日涨知识**  
  
权限提升  
（escalation of privilege）  
  
任何攻击者或利用，将他们的访问权限从正常的用户账户扩展到管理员特权。  
  
  
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
  
