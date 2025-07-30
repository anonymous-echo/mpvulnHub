> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503607&idx=1&sn=44581e3d24968215d02fb7b63ed254d6

#  安全热点周报：Fortinet 公开 FortiWeb 中的严重预身份验证 RCE 漏洞  
 奇安信 CERT   2025-07-14 10:07  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">加拿大一省级电力公司遭勒索攻击：电表通信瘫痪数月 抄表员只能入户抄表</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">巴西央行供应商遭黑，多家金融机构超13亿元准备金被盗</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">万余条公民个人数据被非法获取出售，乌鲁木齐某房产局工作人员涉案</span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Fortinet FortiWeb SQL注入漏洞安全风险通告**  
  
  
7月12日，奇安信CERT监测到官方修复Fortinet FortiWeb SQL注入漏洞(CVE-2025-25257)，该漏洞源于Fortinet FortiWeb Fabric Connector 组件在认证处理中没有严格校验输入参数，攻击者可在 Authorization: Bearer 头中注入恶意SQL语句，实现远程代码执行获取服务器权限。目前该漏洞技术细节与POC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现，建议客户尽快做好自查及防护。  
  
  
**2.契约锁电子签章系统pdfverifier远程代码执行漏洞安全风险通告**  
  
  
7月12日，奇安信CERT监测到官方修复契约锁电子签章系统pdfverifier远程代码执行漏洞(QVD-2025-27432)，该漏洞源于电子签章系统在处理特定数据格式时，存在解析差异导致安全机制被绕过，远程未经身份验证的攻击者可在服务器上执行任意系统命令，可能导致服务器被完全控制、数据泄露或业务系统沦陷。奇安信威胁情报中心安全研究员已成功复现漏洞。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**3.泛微E-cology9前台SQL注入漏洞安全风险通告**  
  
  
7月10日，奇安信CERT监测到官方修复泛微E-cology9 SQL注入漏洞(QVD-2025-26680)，该漏洞源于对用户传入的参数没有严格校验，攻击者可利用该漏洞获取数据库敏感信息，进而获取服务器权限。奇安信威胁情报中心安全研究员已成功复现漏洞。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**4.Git远程代码执行漏洞安全风险通告**  
  
  
7月9日，奇安信CERT监测到官方修复Git 远程代码执行漏洞(CVE-2025-48384)，该漏洞源于Git 的路径解析逻辑错误，攻击者通过在子模块路径中注入回车符篡改配置，导致用户递归克隆（git clone --recursive）时触发恶意钩子脚本，最终实现远程代码执行。目前该漏洞技术细节与POC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**5.Redis hyperloglog远程代码执行漏洞安全风险通告**  
  
  
7月8日，奇安信CERT监测到官方修复Redis hyperloglog远程代码执行漏洞(CVE-2025-32023)，该漏洞产生的原因是Redis在处理hyperloglog操作时，未对输入字符串进行严格验证，导致经过身份验证的本地用户可以使用特制的字符串来触发hyperloglog操作中的堆栈/堆越界写入，从而可能导致远程代码执行。目前该漏洞POC已在互联网上公开，奇安信威胁情报中心安全研究员已成功复现。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
**PART****0****2**  
  
  
**安全事件**  
  
  
**1.供应商防护不当，麦当劳AI招聘助手暴露了约6400万条应聘者个人数据**  
  
  
7月9日The Daily Beast消息，两位安全研究员发现，麦当劳用来招聘新员工的“Olivia”AI聊天机器人存在漏洞，可通过弱密码进入后台系统，并通过某个API遍历应聘者的个人信息和聊天记录等。只需修改应聘者ID，就能查看对应人员和聊天机器人的聊天记录及姓名、电子邮箱、电话号码等个人信息，这类信息预计有6400万条。据悉，这款AI招聘助手由供应商Paradox.ai开发并提供服务，该公司表示已修复漏洞，该漏洞未遭受恶意利用，公司后续将建立漏洞奖励计划以提升安全能力。  
  
  
原文链接：  
  
https://www.thedailybeast.com/hackers-used-simple-password-to-access-mcdonalds-ai-hiring-bot-applicant-data/  
  
  
**2.加拿大一省级电力公司遭勒索攻击：电表通信瘫痪数月 抄表员只能入户抄表**  
  
  
7月9日Infosecurity Magazine消息，加拿大新斯科舍电力公司披露称，自4月下旬公司发现遭受勒索软件攻击以来，客户电表的网络通信一直不畅，用电数据无法上传至系统，被迫暂停计费功能。该公司表示，近期准备开启计费账单，将派出抄表员入户抄表，以向客户提供准确账单，未能抄表的客户将提供预估账单。据悉，此次攻击还导致客户数据泄露，约28万名加拿大用户受到影响。  
  
  
原文链接：  
  
https://www.infosecurity-magazine.com/news/ransomware-nova-scotia-power-meter/  
  
  
**3.IT分销巨头英迈遭勒索攻击服务瘫痪近一周，中国客户订单或受扰乱**  
  
  
7月8日DarkReading消息，跨国IT分销巨头英迈（Ingram Micro）披露称，公司遭受勒索攻击致使业务服务瘫痪近一周，目前攻击已被遏制，受影响系统已得到修复，正在努力恢复上线。据悉，由于服务瘫痪，大量客户无法在线提交订单，官方后续称恢复了英国、德国、中国等部分国家的订单服务，可通过电话或邮件进行处理。有消息人士透露，疑似SafePay勒索软件组织通过英迈内部的Palo Alto Network VPN平台入侵进内网，英迈的下游客户担忧可能被牵连攻击。Palo Alto Network称攻击者通常利用被盗凭证或网络配置错误获取VPN访问权限。  
  
  
原文链接：  
  
https://www.darkreading.com/cyberattacks-data-breaches/ransomware-attack-outage-ingram-micro  
  
  
**4.大疆无人机军用固件厂商被黑客攻击，俄军无人机集体瘫痪**  
  
  
7月8日The Record消息，一家为俄罗斯军方提供大疆无人机军用定制固件的开发团队在Telegram 上发布声明，承认其“1001”固件的分发基础设施遭遇黑客入侵。攻击者不仅侵入其远程服务器系统，还在用于更新无人机的“终端设备”上显示伪造信息，最终致使整个更新体系瘫痪。虽然开发者声称固件本身未被篡改，但他们建议前线操作者立即断开连接，以防更深层入侵。据开发团队称，截至2025年3月，已有超20万架无人机刷入“1001”固件（较2024年8月的10万架翻了一倍），实际部署规模不容小觑。  
  
  
原文链接：  
  
https://therecord.media/cyberattack-russia-firmware-blow-hackers  
  
  
**5.万余条公民个人数据被非法获取出售，乌鲁木齐某房产局工作人员涉案**  
  
  
7月7日法治日报消息，新疆乌鲁木齐市公安局高新区分局网安部门破获一起侵犯公民个人信息案，涉及乌鲁木齐住房信息的万余条公民个人数据被非法获取、出售，其中，某房产局一名工作人员为赚“外快”，竟然收集业主信息转卖，成为这条非法买卖公民个人信息黑灰产业链的源头。某房产局聘用工作人员杨某为了赚取“外快”，利用工作便利，收集包含业主姓名、房屋面积、位置以及手机号码等信息，将相关信息卖给外部人员用于电话推销和广告推广，造成被非法获取的公民个人信息不断扩散。目前，涉案的乌鲁木齐市某房产部门聘用人员杨某及其他三名主要参与人员涉嫌违法犯罪，已被依法采取刑事强制措施。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/fpgDojPJRwCC13SkXrhqxg  
  
  
**6.侵入学校系统获取保密试卷，西交利物浦大学三名学生被开除**  
  
  
7月4日中国青年报消息，多名网友在社交媒体平台发布消息称，西交利物浦大学在其官网发布了“关于给予三名学生开除学籍处分的公告”，但公告随后被删除。公告显示，三名学生因非法侵入学校信息系统获取保密试卷、向他人出售试卷谋取不当利益等原因，学校拟给予其开除学籍处分。据扬子晚报报道，西交利物浦大学教务办公室一名工作人员回应称，内部确实收到了关于此事的邮件，三名学生因非法获取试卷等问题被开除的情况属实。其中，沈某某非法侵入学校信息系统获取保密试卷，向他人出售试卷谋取不当利益；朱某某通过技术手段登录学校系统，非法获取保密试卷，并购买违法获取的考试试卷进行二次销售，从中获利；钱某某提供登录学校信息系统获取保密试卷的技术支持，参与销售环节，从中获利。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/HV_3TvIob3BDrjy66q-tng  
  
  
**7.巴西央行供应商遭黑，多家金融机构超13亿元准备金被盗**  
  
  
7月2日路透社消息，巴西中央银行表示，技术服务提供商C&M Software报告称系统遭遇网络攻击，该行已要求C&M中止金融机构客户对相关基础设施的访问。该公司主要为缺乏自有连接基础设施的金融机构提供服务。C&M Software商务总监Kamal Zogheib表示，公司是此次网络攻击的直接受害者，攻击者通过使用客户凭证实施欺诈性操作，试图非法访问公司的系统和服务。据悉，6家金融机构的央行准备金账户遭到未授权访问，其中仅BMP公司就被盗走超10亿雷亚尔（约合人民币13.2亿元）资金。  
  
  
原文链接：  
  
https://www.reuters.com/world/americas/brazils-cm-software-hit-by-cyberattack-central-bank-says-2025-07-02/  
  
  
**PART****0****3**  
  
  
**政策法规**  
  
  
**1.欧盟委员会公布《通用人工智能实践准则》**  
  
  
7月10日，欧盟委员会公布了《通用人工智能实践准则》（以下简称《准则》）最终版本，标志着欧盟在AI治理领域再度迈出关键一步。作为一项自愿性指导工具，《准则》旨在助力企业更好地遵守欧盟《人工智能法案》中关于通用人工智能的相关规定，其核心内容由透明度、版权以及安全与保障三个关键方面组成。在透明度方面，《准则》要求所有通用AI模型提供商必须保持足够的透明度，以便下游开发者能够更好地理解和集成相关技术。《准则》设计了一份用户友好型的“模型文档表”，帮助供应商系统化地记录关键信息。在版权方面，《准则》为所有模型提供商制定了符合欧盟版权法的具体政策框架，平衡技术应用与知识产权保护之间的关系。在安全与保障方面，《准则》中关于安全与保障的部分仅适用于少数最先进模型供应商，这类模型可能会带来系统性威胁（如降低生化武器开发难度、模型失控等）。《准则》要求提供商必须建立严格的风险评估机制，并采取有效措施降低潜在风险。  
  
  
原文链接：  
  
https://digital-strategy.ec.europa.eu/en/policies/contents-code-gpai  
  
  
**2.供应链安全两项重要团体标准正式发布**  
  
  
7月8日，根据《中国网络空间安全协会团体标准管理办法（试行）》的有关规定，经评审组专家审查通过，中国网络空间安全协会批准，《信息与通信技术和服务供应商安全要求》、《信息与通信技术产品供应链安全测试方法》两项团体标准正式发布，自2025年8月8日起实施。第一项标准规定了信息与通信技术和服务供应商中六类供应商（系统开发、产品供应、运维服务、建设、云服务、数据服务）在管理制度、组织机构和人员、供应活动各环节中的安全能力。第二项标准规定了信息与通信技术产品供应链安全测试的技术规范，包括开展软件成分安全测试、二进制软件基因安全测试、动态应用安全测试、静态应用安全测试、容器镜像安全测试等。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/mlDDTHIUrvv13waoD4ZOuA  
  
  
**3.教育部办公厅印发《关于组织实施数字化赋能教师发展行动的通知》**  
  
  
7月7日，教育部办公厅印发《关于组织实施数字化赋能教师发展行动的通知》。该文件提出了6方面14项重点任务，其中包括“增强数字安全保障”任务。具体包括研究制定教师生成式人工智能应用指引，强化教师在数字化应用实践中的伦理责任和行为规范，合理合规使用数字技术。地方、学校要建立健全教师数据安全保障机制，开展数字伦理主题教育，加强教师网络行为监管，引导教师在数字教育理论学习与实践探索中涵养高尚师德和教育家精神。  
  
  
原文链接：  
  
http://www.moe.gov.cn/srcsite/A10/s7034/202507/t20250704_1196586.html  
  
  
**4.中国互联网协会发布《移动互联网应用服务用户权益保护合规管理指南（2025年）》**  
  
  
7月3日，中国互联网协会和中国信息通信研究院在京联合发布《移动互联网应用服务用户权益保护合规管理指南（2025年）》。该文件根据当前的用户权益保护相关规定将移动互联网应用服务用户权益保护合规归纳总结为六大重点方面，包括服务提供、个人信息保护、算法推荐、服务收费、用户投诉处理、客户热线服务，并梳理了各方面所须遵循的现行有效的合规要求，为移动互联网应用服务提供者开展用户权益保护合规管理工作提供参考。  
  
  
原文链接：  
  
https://www.isc.org.cn//profile//2025/07/04/18307f68-0e86-4028-af6f-826d4a8b1710.pdf  
  
  
**往期精彩推荐**  
  
  
[【已复现】Fortinet FortiWeb SQL注入漏洞(CVE-2025-25257)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503602&idx=1&sn=b6dc54a7100f76968a25f6db47d5e0eb&scene=21#wechat_redirect)  
  
  
[【已复现】契约锁电子签章系统 pdfverifier 远程代码执行漏洞(QVD-2025-27432)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503602&idx=2&sn=e1e4339c66bfeef7053ebf82a7b737eb&scene=21#wechat_redirect)  
  
  
[【已复现】泛微E-cology9 前台SQL注入漏洞(QVD-2025-26680)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503591&idx=1&sn=d2d745e2f4f838c527281205db85b1b4&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
