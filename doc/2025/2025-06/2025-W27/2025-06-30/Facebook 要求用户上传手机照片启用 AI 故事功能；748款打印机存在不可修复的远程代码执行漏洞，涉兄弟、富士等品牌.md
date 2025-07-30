> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611207&idx=1&sn=40ed5bd422bc36c920b02a4fdd6a6c89

#  Facebook 要求用户上传手机照片启用 AI 故事功能；|748款打印机存在不可修复的远程代码执行漏洞，涉兄弟、富士等品牌  
 黑白之道   2025-06-30 02:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**Facebook 要求用户上传手机照片启用 AI 故事功能，引发隐私争议；**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliayHI4AXxL1jL9qQla1ZCKtxW0eia8Ay0pcuEibIak4FiaNicbjqkcQ3wJHLjbtPicwJhRJ57DoeED9OSg/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
Facebook 正在测试一项新的 AI 功能，鼓励用户将手机相册中的照片上传至云端，以生成故事、拼图等内容创意。这一做法虽被标榜为“仅用户可见”，却在网络上引发了广泛的隐私担忧。  
  
据 TechCrunch 报道，部分美国和加拿大用户在创建 Facebook 故事时，收到弹窗提示请求“允许云处理”，以便系统基于照片的时间、地点和主题自动生成内容建议。Meta 表示，上传内容不会用于广告投放，但会被 AI 分析并用于“安全性和完整性”检查。  
  
尽管功能为自愿启用（opt-in），Meta 明确用户一旦同意，即表示接受 AI 条款，包括对其媒体文件和面部特征的分析权限。这让部分隐私专家感到不安——即使照片不直接用于广告，仍可能被用于 AI 模型训练或行为建模，长期追踪用户习惯。  
  
Meta 表示，用户可随时关闭该功能，但由于处理发生在云端，外界对其数据保留时长、存储地点和访问权限仍存在质疑。  
  
这项更新也被视为大厂竞相推动 AI 功能的一部分。此前，Meta 在欧盟获得隐私监管批准后，已开始使用用户公开数据训练 AI；而在巴西，因隐私争议，其生成式 AI 工具已被叫停。  
  
与此同时，德国隐私监管机构正呼吁苹果和谷歌下架 DeepSeek 应用，原因是其将用户数据传输至中国，并违反了欧盟《通用数据保护条例》（GDPR）。有消息称该服务协助中国军方和情报系统进行信息收集。  
  
在全球 AI 快速发展的背景下，Facebook 的这项新功能提醒我们，便利背后往往隐藏着对隐私边界的重新定义。在用户分享前，是否清楚知情、是否真正自主选择，将成为未来科技伦理的关键议题。  
  
**748款打印机存在不可修复的远程代码执行漏洞，涉兄弟、富士等品牌**  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38YqehzWBYy60jRGOdTNREeHibicib2hb58R0euuxHoKicQZVPOkrLMqiaTKj10lEfIW2eDibRhrPSy8heA/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
  
Rapid7 近日曝光了一系列影响深远的安全漏洞，波及兄弟（Brother）、富士、理光和东芝泰格四大厂商的打印机产品线。 8 个不同 CVE 编号的漏洞共影响 748 款打印机、扫描仪和标签打印机，对企业和消费级环境均构成重大安全威胁。  
  
  
**Part01**  
### 高危认证绕过漏洞  
  
  
最严重的漏洞被标记为 CVE-2024-51978（CVSS 评分 9.8），该认证绕过漏洞允许远程攻击者在无需认证的情况下，仅凭设备序列号即可推导出默认管理员密码。  
  
  
Rapid7 解释称： "这是由于发现了  
兄弟（Brother）打印机  
使用的默认密码生成程序。该程序会将序列号转换为默认密码。" 更令人担忧的是，该漏洞无法通过固件更新完全修复。  
兄弟（Brother）  
不得不修改受影响设备的生产流程，这意味着只有新生产的设备才能解决问题。  
  
  
**Part02**  
### 远程代码执行攻击链  
  
  
获取管理员权限后，攻击者可进一步利用高危的基于栈的缓冲区溢出漏洞（CVE-2024-51979，CVSS评分7.2），该漏洞  
涉及栈缓冲区溢出，经认证的攻击者可加以利用。结合 CVE-2024-51978，攻击者能实现完整的远程代码执行。  
  
  
Bambanek Consulting的John Bambanek指出："打印机通常属于'即插即忘'类IT设备，容易忽略更新和安全补丁。但它们也具有操作系统，攻击者可利用其进行横向移动和持久化驻留。"  
  
  
**Part03**  
### 其他相关漏洞  
  
  
此外，Rapid7 报告还列出了六个相关的额外漏洞：   
- CVE-2024-51977 ：通过 HTTP/IPP 服务造成信息泄露   
  
- CVE-2024-51980/CVE-2024-51981 ：可实现网络横向移动的服务端请求伪造（SSRF）  
  
- CVE-2024-51982/CVE-2024-51983 ：导致设备崩溃的拒绝服务漏洞   
  
- CVE-2024-51984 ：从 LDAP 和 FTP 等配置的外部服务泄露密码  
  
**Part04**  
### 影响范围与修复建议  
  
  
据统计，  
689款兄弟（Brother）设备受到影响以外，这些漏洞还影响46款富士胶片、5款理光、2款东芝泰格和6款柯尼卡美能达机型。  
Rapid7 与 JPCERT/CC 和 Brother 进行了为期 13 个月的协调披露，目前已有固件更新可缓解 8 个漏洞中的 7 个。  
  
  
对于  
最严重的漏洞  
 CVE-2024-51978，  
兄弟（Brother）  
提供了临时解决方案，并更新了未来型号的生产流程。 用户应立即采取以下措施：   
- 立即更新固件  
  
- 修改默认管理员凭证  
  
- 查阅厂商公告获取额外缓解措施  
  
> **文章来源 ：安全圈、freebuf******  
  
  
**精彩推荐**  
  
  
  
  
# 乘风破浪|华盟信安线下网络安全就业班招生中！  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575781&idx=2&sn=ea0334807d87faa0c2b30770b0fa710d&chksm=83bdf641b4ca7f5774129396e8e916645b7aa7e2e2744984d724ca0019e913b491107e1d6e29&scene=21#wechat_redirect)  
  
  
# 【Web精英班·开班】HW加油站，快来充电！  
  
  
‍[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650594891&idx=1&sn=b2c5659bb6bce6703f282e8acce3d7cb&chksm=83bdbbafb4ca32b9044716aec713576156968a5753fd3a3d6913951a8e2a7e968715adea1ddc&scene=21#wechat_redirect)  
  
  
‍  
# 始于猎艳，终于诈骗！带你了解“约炮”APP  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650575222&idx=1&sn=ce9ab9d633804f2a0862f1771172c26a&chksm=83bdf492b4ca7d843d508982b4550e289055c3181708d9f02bf3c797821cc1d0d8652a0d5535&scene=21#wechat_redirect)  
  
**‍**  
  
  
