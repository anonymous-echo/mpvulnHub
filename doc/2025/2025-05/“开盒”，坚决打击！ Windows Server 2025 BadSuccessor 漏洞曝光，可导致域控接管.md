#  “开盒”，坚决打击！| Windows Server 2025 "BadSuccessor" 漏洞曝光，可导致域控接管   
e安在线  e安在线   2025-05-28 04:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1Y08O57sHWiahTldalExhOyzXNMO6kcO7ULmiclhSZfg8zVMLHEMUGBu3lBjFbjib8vsYDZzplofMSC7epkHHWpibw/640?wx_fmt=png&from=appmsg "")  
# “开盒”，坚决打击！  
  
**中央网信办部署进一步加强“开盒”问题整治工作**  
  
近日，中央网信办专门印发通知，从阻断“开盒”信息传播、完善预警机制、加大惩治力度、优化保护措施、加强宣传引导等多个维度明确工作要求，督促各地网信部门、各网站平台进一步强化“开盒”问题整治工作。同时，召开专题部署会议，要求微博、腾讯、抖音、快手、百度、小红书、知乎、哔哩哔哩、豆瓣等多家重点网站平台，对照通知抓好各项任务落实，切实履行主体责任，  
**以“零容忍”态度坚决打击“开盒”乱象。**  
  
  
中央网信办有关负责同志表示，“开盒”问题直接关系人民群众切身利益，近段时间以来，网信部门结合职责，深入开展整治工作，全面清理各类涉“开盒”违法违规信息，从严处置传播相关内容的账号和群组，依法按程序处罚3家大型网站平台，组织重点网站平台定期发布治理公告，公布典型案例，并向公安机关通报违法犯罪线索。  
  
  
中央网信办有关负责同志强调，利用“开盒”等方式非法获取并公开他人个人信息，涉嫌违法犯罪，性质极为恶劣。下一步，中央网信办将继续坚持高强度打击和高力度保护并重，着力做好“开盒”问题整治工作。  
**一是全力阻断传播渠道。**  
督促网站平台深入清理各类违法发布个人信息，诱导网民跟进泄露隐私，借机进行攻击谩骂、嘲讽贬低的内容，清理教授、买卖或者提供“开盒”方法、教程和服务等信息内容，对于组织煽动“开盒”、提供“开盒”服务等账号、群组，一律予以关闭或者解散。  
**二是升级完善保护措施。**  
指导网站平台在前期治理网络暴力的基础上，进一步升级完善防护措施，加大“开盒”风险提示力度，设置涉“开盒”举报快速入口，及时核实网民投诉举报，最大限度帮助网民防范和处置“开盒”问题风险。  
**三是加大打击惩治力度。**  
结合个人信息保护系列专项行动，深入治理违法违规收集使用个人信息等问题，会同有关部门严厉打击泄露、盗取、贩卖个人信息，以及利用个人信息开展违法犯罪活动等行为。此外，也希望广大网民提高防“开盒”意识，强化个人信息保护，自觉抵制相关行为，共同营造清朗有序的网络空间。  
#   
# Windows Server 2025 "BadSuccessor" 漏洞曝光  
# 可导致域控接管  
#   
### Part01  
### 漏洞概述  
  
  
Windows Server 2025操作系统中新发现的"BadSuccessor"安全漏洞（CVE编号待分配）允许攻击者完全接管Active Directory（活动目录）域控制器。目前漏洞验证代码（PoC）已在安全社区流传，但微软尚未发布官方补丁。  
  
  
![漏洞验证截图](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iccVtiaSzLOdiaOWSeZ0SmRIqJfkTrN6q5sEZEO5Ek6t7vr6YdPSLq0ic7Br3Lh2SkU4bM5B0nTPtvXg/640?wx_fmt=jpeg&from=appmsg "")  
  
图片来源：Logan Goins  
  
### Part02  
### 技术影响  
  
  
该漏洞属于权限提升类缺陷，通过篡改域控的dMSA（动态管理系统账户）验证机制实现域环境接管。攻击者利用此漏洞可：  
  
- 绕过身份认证获取域管理员权限  
  
- 在目标网络内横向移动  
  
- 部署持久化后门  
  
- 窃取或篡改域内所有凭据数据  
  
### Part03  
### 当前状态  
  
  
网络安全研究人员证实：  
  
- 漏洞影响Windows Server 2025所有已发布版本  
  
- 攻击复杂度评级为"低"（无需特殊权限即可利用）  
  
- 微软安全响应中心已确认收到报告，但未提供补丁时间表  
  
声明：除发布的文章无法追溯到作者并获得授权外，我们均会注明作者和文章来源。如涉及版权问题请及时联系我们，我们会在第一时间删改，谢谢！文章来源：网信中国、  
FreeBuf、  
参考来源：  
  
Windows Server 2025 “BadSuccessor” Flaw Allows Domain Takeover (PoC Available, No Patch)  
  
https://securityonline.info/windows-server-2025-badsuccessor-flaw-allows-domain-takeover-poc-available-no-patch/  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1Y08O57sHWiaM9uv5Q89hYMT8zuKQtQYuvSPy0HyyLwRShZOMcoGgoBy6qiatgDhW3UhCXGVXiaEbS8ANmZwViaMAw/640?wx_fmt=jpeg&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
