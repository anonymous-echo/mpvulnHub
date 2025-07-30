#  【漏洞复现】瑞友天翼应用虚拟化系统appsave SQL注入漏洞   
 云弈安全   2024-05-17 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/73HCAFeXzF1cZHEeG0rTLk5PAntz4O3l13lyNRPHrNlIMFpf1ZjqImUaTDpCo6Iib693uGxaUqOuicbRiax9NDmkA/640?wx_fmt=gif&from=appmsg "")  
  
**01**  
  
**漏洞信息**  
  
瑞友天翼应用虑拟化系统是基于服务器计算架构的应用虚拟化平台。它将用户各种应用软件集中部署在瑞友天翼服务器(群)上，客户端通过WEB即可快速安全的访问经服务器上授权的应用软件，实现集中应用、远程接入、协同办公等，从而为用户打造集中、便捷、安全、高效的虚拟化支撑平台。  
  
近日，云弈安全团队发现了瑞友天翼应用虚拟化系统sql注入漏洞，该漏洞允许攻击者可以通过在用户输入的数据中插入恶意SQL语句来攻击Web应用程序，获取数据库数据等。  
  
**02**  
  
**漏洞描述**  
  
**·**  
  
  
**漏洞成因**  
  
瑞友天翼应用虚拟化系统中的\Home\Controller\AdminController存在appsave/appdel两个无需鉴权并且存在SQL注入的风险的接口。攻击者可利用php PDO默认支持堆叠的方式使用堆叠写入恶意文件导致RCE。  
  
**·**  
  
  
**利用特征**  
  
攻击者可以利用该漏洞通过以下方式进行攻击：  
- **恶意输入点：**  
  
在应用程序的 appsave 或 appdel 功能中，攻击者可能会发现输入验证不足的地方，可以插入恶意的SQL命令。  
  
这些输入点可能是表单、URL参数、HTTP头部或任何与数据库交互的界面。  
- **典型的攻击载荷：**  
  
' OR '1'='1：一个简单的SQL注入试探，用于改变原始SQL语句的逻辑。  
  
'; DROP TABLE users; --：一个更危险的攻击，尝试删除数据库中的表。  
  
使用堆叠查询（在一条SQL语句后加分号开始新的SQL命令）来进一步控制数据库。  
- **错误消息：**  
  
如果应用程序未正确处理SQL错误，攻击尝试可能会导致数据库错误信息泄露，如“MySQL syntax error”或“ORA-01756”。这些错误可以被攻击者用来收集关于数据库结构的信息，优化进一步的攻击。  
  
**·**  
  
  
**漏洞影响**  
  
该漏洞的危害主要体现在：  
- **数据泄露：**  
  
攻击者可以通过注入恶意SQL语句来获取数据库中的敏感信息，如用户密码、信用卡信息；  
- **数据篡改：**  
  
攻击者可以利用注入攻击修改或删除数据库中的数据，如修改用户账户信息或删除关键数据；  
- **服务器攻击：**  
  
攻击者可以利用注入攻击在服务器上执行恶意代码，如上传恶意脚本或获取服务器的管理员权限；  
- **服务拒绝：**  
  
攻击者可以通过注入攻击导致服务器宕机或无法正常工作，从而影响服务的可用性。  
  
**03**  
  
**影响版本**  
  
Version < 7.0.5.1  
  
**04**  
  
**解决方案**  
  
**·**  
  
  
**临时修复建议**  
  
如不影响业务，建议配置URL访问控制策略，只允许白名单用户访问。  
  
**·**  
  
  
**升级修复方案**  
  
厂商已发布修复版本，请升级至 7.0.5.1 或之后的版本：  
  
http://www.realor.cn/product/tianyi/  
  
**·**  
  
  
**云弈安全解决方案**  
  
“天视”资产风险监控系统已于第一时间更新插件，可以对以上漏洞进行检测。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/73HCAFeXzF1cZHEeG0rTLk5PAntz4O3lLy3Ow3a8uEQpF3YrQvIPz1JpgHvNxMeQQWm7okP0H5QAlKEoLb7I4w/640?wx_fmt=png&from=appmsg "")  
  
**05**  
  
**漏洞复现**  
  
查看版本信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/73HCAFeXzF1cZHEeG0rTLk5PAntz4O3lFaSjfyOFKk9dpIVpcmxNgwWLibeEsGn4Qr9QibRET1wNIryxdfiaiaiaiaHw/640?wx_fmt=png&from=appmsg "")  
  
构造SQL注入payload获取数据库信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/73HCAFeXzF1cZHEeG0rTLk5PAntz4O3lyUzTicKRO5PuhYHMKXtAQ1LvVuBWj9zcot1F6wecFm9aoefHhFMibQbA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**关于我们**  
  
  
北京云弈科技有限公司是一家专注于自主研发的国家高新技术企业和“专精特新”企业，致力于国家网络空间安全监测、防护和治理，聚焦于攻防能力与产品能力一体化输出的安全服务商。  
  
基于实战对抗优势，构建了六位一体的纵深安全防御体系，研发出云戟主机自适应安全、弈盾网站云防御、天视资产风险监控、云弈国密堡垒机、海御异常流量清洗、幻鲸网络诱捕等系列产品，完成了产品与各类国产化操作系统、国产化芯片的适配，实现了自主可靠、安全可控。同时也提供渗透测试、红蓝对抗、重保服务、应急响应、等保咨询、密评咨询等安全运营服务，为各行业提供攻防一体化解决方案。  
  
凭借攻防一体化安全能力解决方案，已获得了政府、运营商、金融、能源、教育、互联网等行业的数千家客户应用与认可。云弈科技致力于国家网络空间安全的技术创新和服务输出，积极履行社会责任，为构建安全可靠的数字化强国贡献力量。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/73HCAFeXzF1cZHEeG0rTLk5PAntz4O3lqVRYgNO2rg3OkNliaQUdHXtjV7CXm2I3aicYmiaMXBL1U0HsChAWESoow/640?wx_fmt=gif&from=appmsg "")  
  
  
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
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/73HCAFeXzF1cZHEeG0rTLk5PAntz4O3leeyxc6KcwMfpHo1wVbN0ofO4dwKMngicofO7xgPMbhADLRrXu6mm2AQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
