#  安全热点周报：黑客利用 Twilio Authy 漏洞窃取数百万用户信息   
 奇安信 CERT   2024-07-29 20:01  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 国家发改委《电力监控系统安全防护规定》公开征求意见</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 乌克兰一城市供暖系统遭网络攻击被关闭，部分居民在寒冬下停暖近2天</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="outline: 0px;visibility: visible;">• 墨西哥ERP软件巨头云泄露超7亿条记录，内含密钥等敏感信息</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
****  
  
**新增在野利用**  
  
  
**1.****Twilio Authy 信息泄露漏洞(CVE-2024-39891)**  
  
  
7月 23 日，美国网络安全和基础设施安全局 (CISA) 在其已知利用漏洞 (KEV) 目录中添加Twilio Authy 信息泄露漏洞(CVE-2024-39891)，Twilio Authy 的 API 中包含一个信息泄露漏洞，该漏洞允许未经身份验证的端点接受包含电话号码的请求，并返回有关该电话号码是否在 Authy 注册的信息。  
  
6 月底，一个名为 ShinyHunters 的黑客泄露了一个 CSV 文本文件，其中包含他们声称的在 Authy 服务上注册的 3300 万个电话号码。该 CSV 文件包含 33,420,546 行，每行包含一个帐户 ID、电话号码、“over_the_top”列、帐户状态和设备数量。  
  
这些数据是通过将大量电话号码列表输入不安全的 API 端点而汇编而成的。如果号码有效，端点将返回有关在 Authy 注册的关联帐户的信息。  
  
虽然 Authy 抓取的数据仅包含电话号码，但对于想要通过短信网络钓鱼和 SIM 卡交换攻击来窃取账户的用户来说，这些数据仍然具有优势。  
  
ShinyHunters 在他们的帖子中提到了这一点，并表示“你们可以在 gemini 或 Nexo db 上加入”，建议黑客组织将电话号码列表与所谓的 Gemini 和 Nexo 数据泄露中泄露的电话号码列表进行比较。如果发现匹配，黑客组织可能会尝试执行 SIM 卡交换攻击或网络钓鱼攻击来破坏加密货币交易账户并窃取所有资产。  
  
Twilio 现已发布新的安全更新，并建议用户升级到包含安全更新的 Authy Android (v25.1.0) 和 iOS App (v26.1.0)。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/hackers-abused-api-to-verify-millions-of-authy-mfa-phone-numbers/  
  
**PART****0****2**  
  
  
**安全事件**  
  
  
**1.美国政府最大IT服务商发生数据泄露事件**  
  
  
7月24日彭博社消息，知情人士透露，黑客泄露了从美国联邦政府最大IT服务提供商之一的Leidos Holdings Inc.公司窃取的内部文件。Leidos发言人表示：“我们已经确认，这是源于之前第三方供应商Diligent的数据泄露事件，所有必要的通知已在2023年发出。此次事件并未影响我们的网络或任何敏感客户数据。”根据2023年6月在马萨诸塞州提交的文件显示，Leidos使用Diligent系统来托管内部调查中收集的信息。Diligent发言人表示，这次泄露的数据似乎源自2022年其子公司Steele Compliance Solutions遭遇的黑客事件。该子公司于2021年被收购。当时包括Leidos在内的客户不到15家。Leidos主要客户如美国国防部、国土安全部和NASA未立即回应置评请求。  
  
  
原文链接：  
  
https://www.bloomberg.com/news/articles/2024-07-23/hackers-leak-documents-from-pentagon-it-services-provider-leidos  
  
  
**2.乌克兰一城市供暖系统遭网络攻击被关闭，部分居民在寒冬下停暖近2天**  
  
  
7月23日TechCrunch消息，美国工控安全公司Dragos发布报告，披露了一种旨在攻击工业控制系统的新型恶意软件FrostyGoop。Dragos表示，经与乌克兰当局沟通，在今年1月下旬，FrostyGoop曾被用于攻击乌克兰利沃夫市的暖气系统，导致超600栋公寓楼停暖近2天，当时室外温度低于零度。据悉，FrostyGoop恶意软件通过Modbus协议与工控设备交互，该协议被广泛用于工控环境，这意味着FrostyGoop也可被用于攻击其他公司和设施。Dragos称，FrostyGoop是该公司已发现的第九款专门针对工控系统的恶意软件。  
  
  
原文链接：  
  
https://techcrunch.com/2024/07/23/hackers-shut-down-heating-in-ukrainian-city-with-malware-researchers-say/  
  
  
**3.墨西哥ERP软件巨头云泄露超7亿条记录，内含密钥等敏感信息**  
  
  
7月23日HackRead消息，安全研究员Jeremiah Fowler发现，墨西哥最大的ERP软件提供商之一ClickBalance，旗下一个云数据库暴露在公网未设置任何认证措施，导致7.69亿条记录泄露，恶意威胁行为者可以轻而易举地访问这些数据。Fowler向WebsitePlanet报告了这一问题。该报告指出，该数据库包含了潜在的敏感信息，如访问令牌、API密钥、密钥、银行账号、税号和381224个电子邮件地址。目前尚不清楚数据库暴露了多长时间，也不清楚是否有其他人访问过。Fowler发送了负责任的披露通知，几小时后该数据库限制了公共访问。  
  
  
原文链接：  
  
https://hackread.com/mexico-erp-clickbalance-769-million-records-data-leak/  
  
  
**PART****0****3**  
  
  
**政策法规**  
  
  
**1.两部门《国家网络身份认证公共服务管理办法》公开征求意见**  
  
  
7月26日，公安部、国家互联网信息办公室起草了《国家网络身份认证公共服务管理办法（征求意见稿）》，现向社会公开征求意见。该文件共16条，主要包括四个方面的内容：一是明确了国家网络身份认证公共服务和“网号”“网证”等概念；二是明确了公共服务的使用方式和场景；三是强调了公共服务平台和互联网平台的数据和个人信息保护义务；四是明确了公共服务平台和互联网平台违反数据和个人信息保护义务的法律责任。该文件提出，对自愿选择使用“网号”“网证”的用户，除法律法规有特殊规定或者用户同意外，互联网平台不得要求用户另行提供明文身份信息，最大限度减少互联网平台以落实“实名制”为由超范围采集、留存公民个人信息。  
  
  
原文链接：  
  
https://www.cac.gov.cn/2024-07/26/c_1723675813897965.htm  
  
  
**2.国家发改委《电力监控系统安全防护规定》公开征求意见**  
  
  
7月25日，国家发展改革委组织修订了《电力监控系统安全防护规定》（发改委2014年第14号令），形成《电力监控系统安全防护规定》（公开征求意见稿），现向社会公开征求意见。该文件共6章38条，包括总则、安全技术、安全管理、应急措施、监督管理、附则。该文件提出，电力监控系统安全防护应坚持“安全分区、网络专用、横向隔离、纵向认证”结构安全原则，强化安全免疫、态势感知、动态评估和备用应急措施。该文件细化了安全分区保护粒度，强化了安全接入区设置及防护要求，补充了业务横纵向交互、设备选型、安全加固、态势感知等技术要求，以及应急备用等管理措施。该文件首次提出电力监控系统专用安全产品目录及技术规范，以强化供应链管理。  
  
  
原文链接：  
  
https://yyglxxbs.ndrc.gov.cn/file-submission/20240725093559988587.docx  
  
  
**3.李强签署国务院令，公布修订版《中华人民共和国保守国家秘密法实施条例》**  
  
  
7月22日，国务院总理李强日前签署国务院令，公布修订后的《中华人民共和国保守国家秘密法实施条例》，自2024年9月1日起施行。该文件共6章74条，包括总则、国家秘密的范围和密级、保密制度、监督管理、法律责任、附则。该文件要求，县级以上人民政府应当加强保密基础设施建设和关键保密科学技术产品的配备。该文件提出，涉密信息系统按照涉密程度分为绝密级、机密级、秘密级，机关、单位应当按照国家保密规定，对绝密级信息系统每年至少开展一次安全保密风险评估，对机密级及以下信息系统每两年至少开展一次安全保密风险评估，涉密信息系统中使用的信息设备应当安全可靠，以无线方式接入涉密信息系统的，应当符合国家保密和密码管理规定、标准。  
  
  
原文链接：  
  
https://www.gov.cn/zhengce/content/202407/content_6963933.htm  
  
  
**往期精彩推荐**  
  
  
[安全热点周报：本周新增四个在野利用漏洞，Magento、SolarWinds等企业级应用受波及](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501769&idx=1&sn=2edeb62bd20fc5bd84da63caa890e03e&chksm=fe79e351c90e6a4753944bb594a30e2b7bf1dddd44e2f6071ae200c622e71290e1d1d89607eb&token=922035802&lang=zh_CN&scene=21#wechat_redirect)  
[CrowdStrike导致全球性IT基础设施中断事件分析报告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501763&idx=1&sn=3714d555ecf347d22ba237fc80c5131a&chksm=fe79e35bc90e6a4d32699034dcf6c752d63eb31305f62c9a2ff63f852f69c24b89743c314aca&token=922035802&lang=zh_CN&scene=21#wechat_redirect)  
  
[【已复现】Nacos Derby 远程命令执行漏洞(QVD-2024-26473)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247501756&idx=1&sn=d2a6bccad06819cf70176bc02a7ee944&chksm=fe79e324c90e6a32139fd6113ec70cea92a332ab1c089e0b8e3b4676c71774730911e98195de&token=922035802&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
