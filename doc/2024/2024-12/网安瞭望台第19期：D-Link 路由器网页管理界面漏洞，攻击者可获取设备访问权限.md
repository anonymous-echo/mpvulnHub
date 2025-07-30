#  网安瞭望台第19期：D-Link 路由器网页管理界面漏洞，攻击者可获取设备访问权限   
原创 扬名堂  东方隐侠安全团队   2024-12-30 15:50  
  
网安资讯分享  
  
DAILY NEWS AND KNOWLEDGE  
  
  新鲜资讯&知识 抢先了解    
  
隐侠安全客栈  
  
**国内外要闻**  
  
  
**HIPAA 规则：要求 72 小时数据恢复与年度合规审计**  
  
     
   
2024 年 12 月 30 日，拉维・拉克什马南报道了一则关乎医疗行业网络安全与合规的重要资讯。美国卫生及公共服务部（HHS）民权办公室（OCR）针对医疗保健组织提出全新网络安全要求，旨在守护患者数据，抵御潜在网络攻击 。这一提案意图修订 1996 年的《健康保险流通与责任法案》（HIPAA），属于强化关键基础设施网络安全的宏大计划一部分。  
  
    新规聚焦强化电子受保护健康信息（ePHI）的防护，更新 HIPAA 安全规则标准，力求更好应对医疗领域与日俱增的网络威胁。具体而言，组织需审查技术资产清单与网络地图，排查可能危及电子信息系统的潜在漏洞，还要设立流程，确保能在 72 小时内恢复特定电子信息系统与数据。  
  
    此外，新规还有诸多关键条款。比如，至少每 12 个月开展一次合规审计；要求静态与传输中的 ePHI 加密；强制使用多因素认证；部署反恶意软件防护，并清理相关电子信息系统中的冗余软件。《拟议规则制定通知》还规定，医疗实体要实施网络分段，搭建备份及恢复的技术管控，每半年至少进行一次漏洞扫描，每年至少开展一次渗透测试。  
  
    当下，医疗行业沦为勒索软件攻击的 “香饽饽”。这不仅带来财务风险，还因干扰诊断设备与含患者病历的关键系统，危及生命。微软曾指出，医疗组织收集、存储的敏感数据，引得威胁行为者发起勒索攻击，更关键的是巨额赎金赔付的可能性，让其风险飙升，周边医疗机构也会因患者涌入却无力急救而受牵连。据 Sophos 数据，2024 年 67% 的医疗组织遭勒索软件攻击，远超 2021 年的 34%，多数源于漏洞利用、凭证泄露与恶意邮件。超半数数据被加密的医疗组织支付赎金恢复访问，中位数达 150 万美元，而且攻击后的恢复时长也在拉长，仅 22% 的受害者能在一周内完全恢复，远低于 2022 年的 54% 。正如 Sophos 首席技术官所说，医疗信息的高敏感与高需求，让行业被网络罪犯盯上，可多数组织应对乏力。上月，世卫组织也将针对医院和医疗系统的勒索攻击定性为 “生死攸关之事”，呼吁国际合作打击网络威胁。  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4E2AolicQMGIKVvxZfA9CQu0QI2mPzarsrsSpMdRgCksNytvmgW0IadPkULWMQHJ39tgvlLposYqQ/640?wx_fmt=png&from=appmsg "")  
  
****  
超 15000 台四信路由器因默认凭证面临新漏洞利用风险  
  
      
2024 年 12 月 28 日，VulnCheck 有新发现：部分四信（Four-Faith）路由器受到一个高严重性漏洞的影响，且已遭野外恶意利用。该漏洞编号为 CVE-2024-12856 ，CVSS 评分为 7.2，属于操作系统命令注入漏洞，波及 F3x24 与 F3x36 型号的路由器。  
  
    虽说它的严重性因远程攻击者需先成功认证身份而有所降低，但要是路由器的默认凭证没被更改，就可能出现未经授权的操作系统命令执行情况。VulnCheck 详述的攻击事件里，不明威胁行为者利用路由器默认凭证，触发对 CVE-2024-12856 漏洞的利用，还开启反向 shell 以获取持久远程访问权限 。发起攻击的 IP 地址是 178.215.238 [.] 91，此前它还关联过针对四信路由器的另一个远程代码执行漏洞 CVE-2019-12168 的攻击利用行动，威胁情报公司 GreyNoise 记录显示，直到 2024 年 12 月 19 日，还有利用 CVE-2019-12168 的尝试。  
  
    雅各布・贝恩斯在报告中指出：“攻击者至少能通过 HTTP，利用 /apply.cgi 端点，针对四信 F3x24 和 F3x36 型号路由器发起攻击。当通过 submit_type = adjust_sys_time 修改设备系统时间时，系统在 adj_time_year 参数上易受操作系统命令注入的威胁。”Censys 数据表明，有超 15000 台面向互联网的相关设备。已有部分证据显示，针对该漏洞的攻击或许早在 2024 年 11 月初就开始了  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4E2AolicQMGIKVvxZfA9CQujpurvCe572bFuJnerBuM2w75IjXtp52CvvQANyWfA9oI4nAmIh847A/640?wx_fmt=png&from=appmsg "")  
  
  
D-Link 路由器网页管理界面漏洞：攻击者可获取设备访问权限  
  
      
2024 年 12 月 30 日，Dhivya 报道称，在 D-Link DIR-823G 路由器固件版本 1.0.2B05_20181207 的网页管理界面，发现了一个关键漏洞（CVE-2024-13030）。该漏洞源于 / HNAP1 / 端点下各项功能访问控制的不当实施，使得攻击者有机可乘，能利用受影响设备内不完善的访问控制，进而未经授权访问设备，导致系统遭到入侵。  
  
    在网页管理界面中，诸如设置自动重启、设置客户端信息、设置 DMZ 设置、设置防火墙设置、设置家长控制信息、设置 QoS 设置以及设置虚拟服务器设置等特定操作，都极易遭到操纵。攻击者利用这一漏洞，无需提前认证，就能远程获取未经授权的访问权限，修改路由器设置，甚至完全掌控路由器，而这极有可能致使更广泛的网络受到威胁，特别是那些连接着敏感环境的路由器。  
  
    此漏洞依据多个通用漏洞评分系统（CVSS）版本进行评分：CVSS 4.0 评分为 6.9（中等）；CVSS 3.1 与 3.0 评分为 7.3（高）；CVSS 2.0 评分为 7.5。高分的关键因素在于，攻击者无需物理接触即可远程利用漏洞，无需有效凭证，而且一旦被利用，会危及数据的保密性、完整性与可用性。  
  
从技术细节来看，受影响的路由器功能与家庭网络管理协议（HNAP1）相关联。不当的访问控制（CWE-284）以及错误的权限分配（CWE-266），让攻击者得以提升权限，执行未经授权的指令。针对该漏洞的利用方法已被公开披露，使用受影响固件的 D-Link DIR-823G 路由器的组织与个人，面临的风险愈发升高，毕竟这些设备往往承担着关键的联网功能。  
  
    目前，D-Link 尚未提供补丁或更新来解决这一问题。用户可采取以下措施降低风险：将远程管理访问权限限制在可信任的 IP 地址，或者干脆完全禁用；为本地设备管理设置强壮且独一无二的密码；监控网络流量，留意异常活动迹象；用带有定期安全更新的新型号替换老旧或不受支持的设备。据悉，该漏洞由安全研究员 wxhwxhwxh_mie 发现并上报。网络安全专家提醒 DIR-823G 路由器用户，鉴于利用风险攀升，需迅速行动保障设备安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4E2AolicQMGIKVvxZfA9CQucP33Ih7afzfMqleHjaXJFJoV2UvTSMROj0IoCp0Yxqz11GnmicnEVgA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识分享**  
  
  
### Palo Alto Networks PAN - OS 软件漏洞威胁网络安全  
### 漏洞详情  
- CVE 编号：CVE - 2024 - 3393。  
  
- 危害定级：严重。  
  
- 漏洞标签：Palo Alto Networks PAN - OS 在野利用。  
  
- 披露日期：2024 - 12 - 30。  
  
- 推送原因：漏洞创建。  
  
- 信息来源：  
https://www.cisa.gov/known  
 - exploited - vulnerabilities - catalog。  
  
### 漏洞描述  
  
    Palo Alto Networks 的 PAN - OS 软件在 DNS 安全功能中，于解析和记录畸形 DNS 数据包时存在漏洞。一旦被利用，未经身份验证的攻击者能远程重启防火墙，多次触发此情况会使防火墙进入维护模式。该漏洞源于对异常或特殊条件的不当检查（CWE - 754）。  
  
### 风险影响  
  
    防火墙反复重启或进入维护模式，会严重干扰网络正常运行，使网络防护出现缺口，攻击者可能趁机入侵网络，窃取敏感信息或破坏网络服务，对依赖网络安全防护的企业和组织构成重大威胁。  
###   
### 修复方案  
  
    若有缓解措施，应按照供应商的指示应用；若没有可用的缓解措施，应停止使用该产品。同时，可关注官方发布的补丁或更新版本，及时安装以修复漏洞。  
  
  
CVE-2024-50379/CVE-2024-56337 : Apache Tomcat Patches Critical RCE Vulnerability  
  
🔥EXP: https://github.com/SleepingBag945/CVE-2024-50379  
  
📊 11.5m+ Services are found on http://hunter.how yearly.  
  
🔗Hunter Link:  
  
https://hunter.how/list?searchValue=product.name%3D%22Apache%20Tomcat%22  
  
👇Query  
  
HUNTER :/product.name="Apache Tomcat"  
  
FOFA : product="Apache-Tomcat"  
  
SHODAN : product:"Apache-Tomcat"  
  
📰Refer:https://securityonline.info/cve-2024-56337-apache-tomcat-patches-critical-rce-vulnerability/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH6cPicWuh1ToLX6Hyzr0nB5ZcD0Gn5YQu8xaicQ5tia1Jgke7nsordGXNa0qORraiayIlaMKyRdSzheKA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH6cPicWuh1ToLX6Hyzr0nB5Z2WqkxmSJlmWzCGdKN5VxhgO7ibYdPI5d8MmhfiaV5WYXXj4YibcmztoYg/640?wx_fmt=png&from=appmsg "")  
  
  
  
知识大陆：内部交流群：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icqGYtiaRQqH4E2AolicQMGIKVvxZfA9CQumQscxrAIX0BxgpF351pF8RXD7ggE5sB4shHnNM6lx6FHvcpAIOAiaeQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  
