> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MDY1MDU4MQ==&mid=2247583016&idx=1&sn=3779c200d5b53c656dd00799324e1aea

#  超过84000个Roundcube网络邮件安装受到RCE漏洞影响  
胡金鱼  嘶吼专业版   2025-06-18 07:29  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
最新发现，超过84000个Roundcube网络邮件安装容易受到CVE-2025-49113的攻击，CVE-2025-49113是一个严重的远程代码执行（RCE）漏洞，可公开利用。  
  
该漏洞影响了Roundcube的1.1.0到1.6.10版本，跨越了十年，在安全研究员Kirill Firsov发现并报告后，于2025年6月1日被修补。  
  
该错误源于未处理的$_GET['_from']输入，当会话键以感叹号开始时，会启用PHP对象反序列化和会话损坏。  
  
补丁发布后不久，黑客对其进行了逆向工程，开发了一个有效的漏洞，并在地下论坛上出售。尽管利用CVE-2025-49113需要身份验证，但攻击者声称可以通过CSRF、日志抓取或暴力强制获取有效凭据。目前Firsov在他的博客上分享了有关该漏洞的技术细节，以帮助防御很可能发生的主动利用尝试。  
# 大规模的曝光  
  
Roundcube广泛用于共享主机（GoDaddy, Hostinger， OVH）以及政府，教育和技术部门，在线可见实例超过120万。  
  
威胁监测平台Shadowserver基金会报告称，截至2025年6月8日，其互联网扫描返回了84925个易受CVE-2025-49113攻击的Roundcube实例。  
  
这些案例中的大多数发生在美国（19500）、印度（15500）、德国（13600）、法国（3600）、加拿大（3500）和英国（2400）。  
  
考虑到高风险的利用和潜在的数据盗窃，这些实例的暴露是一个重大的网络安全风险。建议系统管理员尽快更新到解决CVE-2025-49113的1.6.11和1.5.10版本。  
  
目前尚不清楚该漏洞是否被用于实际的攻击，以及规模有多大，但安全研究员建议人们应立即采取行动。如果无法升级，建议限制对webmail的访问，关闭文件上传，添加CSRF保护，阻止有风险的PHP函数，并监控漏洞利用指标。  
  
参考及来源：  
https://www.bleepingcomputer.com/news/security/over-84-000-roundcube-instances-vulnerable-to-actively-exploited-flaw/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icAZ3XYPLkNZE16HxpaZgAUwxz1jADiciaNZjAf0LGna01AGOqIibKTNI7dc4U76cexCJDZTz8XiaTHsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icAZ3XYPLkNZE16HxpaZgAUcVsEePFY7V7eJib23mGgEUiaTiawgbJibD8F636GCA5KNbJ9Y3pSibcB84w/640?wx_fmt=png&from=appmsg "")  
  
  
