#  【漏洞情报】Fortinet FortiOS & FortiProxy越界写入漏洞   
 云弈安全   2024-03-15 18:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/73HCAFeXzF3B7LB7K0pdOIcY6wMFCia7N4pWnNHuMHwW3qfOZmI4tcQsmbhEqWzyTbCRtad6llNSibRr2pqJJHJg/640?wx_fmt=gif&from=appmsg "")  
  
**01**  
  
**漏洞信息**  
  
Fortinet FortiOS是美国飞塔公司的一套专用于FortiGate网络安全平台上的安全操作系统。该系统为用户提供防火墙、防病毒、IPSec/SSLVPN、Web内容过滤和反垃圾邮件等多种安全功能。FortiGate在2月份发布了版本更新，修复了多个中高危漏洞。其中严重级别漏洞之一是 SSL VPN 中未经授权的越界写入漏洞。  
  
**02**  
  
**漏洞描述**  
  
**·**  
  
  
**漏洞成因**  
  
云弈安全团队注意到Fortinet FortiOS和FortiProxy多个版本在SSL VPN组件中，在标头满足特定条件的情况下添加了一些条件，并抛出错误以避免漏洞。在多次尝试下可以使目标崩溃，并且在花费数小时并测试不同的 ROP 链后，能够在目标上实现远程代码执行。  
  
**·**  
  
  
**漏洞影响**  
  
该漏洞的危害主要体现在：  
- **拒绝服务攻击**  
  
- **任意命令执行**  
  
  
  
**03**  
  
**影响版本**  
  
7.4.0 <= FortiOS <= 7.4.2  
  
7.2.0 <= FortiOS <= 7.2.6  
  
7.0.0 <= FortiOS <= 7.0.13  
  
6.4.0 <= FortiOS <= 6.4.14  
  
6.2.0 <= FortiOS <= 6.2.15  
  
6.0.0 <= FortiOS <= 6.0.17  
  
7.4.0 <= FortiProxy <= 7.4.2  
  
7.2.0 <= FortiProxy <= 7.2.8  
  
7.0.0 <= FortiProxy <= 7.0.14  
  
2.0.0 <= FortiProxy <= 2.0.13  
  
FortiProxy 1.2所有版本  
  
FortiProxy 1.1所有版本  
  
FortiProxy 1.0所有版本  
  
**04**  
  
**解决方案**  
  
**·**  
  
  
**临时修复建议**  
  
禁用 SSL VPN（禁用 Web 模式不是有效的解决方法）。  
  
**·**  
  
  
**升级修复方案**  
  
目前该漏洞已经修复，受影响用户可升级到以下版本：  
  
FortiOS 7.4版本：>=7.4.3  
  
FortiOS 7.2版本：>=7.2.7  
  
FortiOS 7.0版本：>= 7.0.14  
  
FortiOS 6.4版本：>= 6.4.15  
  
FortiOS 6.2版本：>= 6.2.16  
  
FortiOS 6.0版本：>= 6.0.18  
  
FortiProxy 7.4版本：>= 7.4.3  
  
FortiProxy 7.2版本：> 7.2.9  
  
FortiProxy 7.0版本：>= 7.0.15  
  
FortiProxy 2.0版本：>= 2.0.14  
  
FortiProxy 1.2版本：迁移到固定版本  
  
FortiProxy 1.1版本：迁移到固定版本  
  
FortiProxy 1.0版本：迁移到固定版本  
  
下载链接：  
  
https://docs.fortinet.com/product/fortigate/7.4  
  
**·**  
  
  
**云弈安全解决方案**  
  
“天视”资产风险监控系统已于第一时间更新插件，可以对以上漏洞进行检测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/73HCAFeXzF3B7LB7K0pdOIcY6wMFCia7NWVhllpbxkIuHib2kGOMiacrHaWeiaA963KmLIQicsFr0ncRee9whiaCX6TA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**关于我们**  
  
  
北京云弈科技有限公司是一家专注于自主研发的国家高新技术企业和“专精特新”企业，致力于国家网络空间安全监测、防护和治理，聚焦于攻防能力与产品能力一体化输出的安全服务商。  
  
基于实战对抗优势，构建了六位一体的纵深安全防御体系，研发出云戟主机自适应安全、弈盾网站云防御、天视资产风险监控、云弈国密堡垒机、海御异常流量清洗、幻鲸网络诱捕等系列产品，完成了产品与各类国产化操作系统、国产化芯片的适配，实现了自主可靠、安全可控。同时也提供渗透测试、红蓝对抗、重保服务、应急响应、等保咨询、密评咨询等安全运营服务，为各行业提供攻防一体化解决方案。  
  
凭借攻防一体化安全能力解决方案，已获得了政府、运营商、金融、能源、教育、互联网等行业的数千家客户应用与认可。云弈科技致力于国家网络空间安全的技术创新和服务输出，积极履行社会责任，为构建安全可靠的数字化强国贡献力量。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/73HCAFeXzF3B7LB7K0pdOIcY6wMFCia7NjQT5YdNsAXLicHnMSOvAU4Za8MytMhe2LNS4CyIZ5tziboiaIuInvDBwA/640?wx_fmt=gif&from=appmsg "")  
  
  
● **权威认可**  
  
  
国家高新技术企业  
  
中关村高新技术企业  
  
北京市“专精特新”中小企业  
  
北京市“创新型”中小企业  
  
《2023信创产业TOP100榜单》TOP100企业  
  
WIA2023创新奖  
  
......  
  
**● 荣誉奖项**  
  
  
中国网络安全产业联盟先进会员  
  
中国网络安全创新百强企业  
  
中国网络安全产业百强企业  
  
2022年中国网安产业潜力之星  
  
2023中国网络安全产业势能榜  
  
【金融】行业年度杰出“创新型”安全厂商  
  
......  
  
● **合作联盟**  
  
  
中国网络安全产业联盟  
  
北京市工商业联合会  
  
中国电子工业标准化技术协会  
  
中国通信企业协会  
  
统信同心生态联盟  
  
UOS主动安全防护计划  
  
海光产业生态合作组织  
  
网络安全服务阳光行动成员  
  
......  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/73HCAFeXzF3B7LB7K0pdOIcY6wMFCia7Nd5ezMyAxe2JojIdOicoY5LRzedE4591qY4dCwu5UzdR96IsPpTfv7ew/640?wx_fmt=jpeg&from=appmsg "")  
  
  
