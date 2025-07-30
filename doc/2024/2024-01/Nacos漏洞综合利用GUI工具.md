#  Nacos漏洞综合利用GUI工具   
 黑白之道   2024-01-14 08:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
### 前言  
###   
  
本工具已经集成Nacos常见漏洞的检测及其利用，工具为GUI版本，简单好用。3.4版本优化了内存马注入处命令执行的代码，可单独检测是否存活，添加了批量扫描等。  
### 工具使用说明(v3.4版本)  
  
**漏洞检测**  
  
漏洞检测支持非常规路径的检查，比如Nacos的路径为   
http://xxx.xxx.xxx.xxx/home/nacos  
 , 只需在目标中填入Nacos的路径即可，指纹识别功能会就去扫描三个路径(" "、"/nacos" 、"/home/nacos")，识别了Nacos才会开启漏洞扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic197HAub9d0Q6rZliaZiasOY3Gt1QNvvNFxGEszcqnxw2W1Vib9iapiaogt1QUGochd4FZQuzzOqfKD38A/640?wx_fmt=png&from=appmsg&wxfrom=13 "")  
  
**权限绕过漏洞利用**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic197HAub9d0Q6rZliaZiasOY3HJYL4xeaWmMEp76oWR20QK5JVYJ63zufk0xPs14panCxt4Nh3DHbRQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**批量检测**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic197HAub9d0Q6rZliaZiasOY3zKcQnwu0ZrDRXHicvWicYAaqu75l5021adQbdULIeStKkFtauQRpHEMQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**SQL注入利用**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic197HAub9d0Q6rZliaZiasOY3avRwPq2IQjhEpI1tlebaQNBsZA8orvkSSwYoRgbEm17WRXXWYzl7JQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内存马注入**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic197HAub9d0Q6rZliaZiasOY3RiaQUHEWjD1Rar2ZH25AkW4utdowgvhjd2XNOZ7MIvoaIX1zicqmvRsA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
# v3.8版本更新  
  
实现了nacos-client yaml 的自动化检测及其利用 ，师傅们可以试试看实战场景下遇到的多不多，工具出现了特殊场景导致的误报漏报欢迎联系我进行更新   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic197HAub9d0Q6rZliaZiasOY3CDuiav2XVZWibBqlhsBIYLicwyiaDmLAUuLwmlYMIqERia4gvpw7B05CCAQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 免责声明  
  
该开源工具是由作者按照开源许可证发布的，仅供个人学习和研究使用。作者及本公众号不对您使用该工具所产生的任何后果负任何法律责任。  
  
**下载地址：https://github.com/charonlight/NacosExploitGUI**  
  
> **文章来源：HACK之道**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
