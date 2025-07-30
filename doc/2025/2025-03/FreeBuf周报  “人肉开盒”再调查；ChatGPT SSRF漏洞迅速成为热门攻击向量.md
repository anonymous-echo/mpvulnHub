#  FreeBuf周报 | “人肉开盒”再调查；ChatGPT SSRF漏洞迅速成为热门攻击向量   
 FreeBuf   2025-03-22 18:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、一周好文，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38XwTgRA48WDosoh2GoRypxFLFAugtFLt5WbbcRYa1x7RTcVTP3fu926JBGZVZa0NlVicmbaEzmCBg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**热点资讯**  
  
  
### 1. “人肉开盒”再调查：网络灰产隐秘升级，记者买到自己的秘密  
  
“开盒”，即利用非法手段获得并公开曝光他人隐私数据与信息。随着网络暴力的升级，“开盒”逐渐从信息曝光演变为“人肉搜索＋系统性暴力”的结合体。有受访者坦言，几乎没有什么办法制止，“只能等言论自然平息”。  
###   
### 2. Windows文件管理器漏洞可导致网络欺骗攻击，PoC已发布  
###   
  
Windows文件管理器漏洞CVE-2025-24071可导致攻击者通过解压文件窃取NTLM哈希，无需用户交互，PoC已发布。  
###   
### 3. ChatGPT SSRF漏洞迅速成为热门攻击向量（含PoC视频）  
  
威胁行为者利用ChatGPT的SSRF漏洞（CVE-2024-27564）针对美国金融和政府机构发起攻击，一周内超过1万次尝试，凸显中等漏洞的潜在危险性。  
###   
### 4. 谷歌以320亿美元收购Wiz，加速AI时代云安全与多云战略  
  
谷歌以320亿美元收购Wiz，加速AI时代云安全与多云战略，提升网络安全能力，抵御新兴威胁，推动多云普及，保护全球客户数据安全。  
###   
### 5. Linux内核越界写入漏洞导致权限提升  
###   
  
Linux内核存在近20年的严重漏洞（CVE-2025-0927），允许本地用户获取root权限，影响多版本系统。Ubuntu已发布修复程序，管理员需立即更新。  
###   
### 6. CISA 警告 NAKIVO 备份漏洞可能被利用进行攻击，PoC 发布  
###   
  
CISA 就NAKIVO 备份和复制解决方案中的一个严重漏洞发出了紧急警告。该漏洞被标记为 CVE-2024-48248，允许未经身份验证的攻击者从运行该软件易受攻击版本的系统中读取任意文件。  
###   
### 7. 砍掉传统产品，押注AI/数据赋能安全：知名头部安全厂商宣布新战略  
###   
  
美国终端安全头部厂商SentinelOne首席执行官Tomer Weingarten日前表示，公司正将资源倾斜至AI驱动的安全和分析技术等高速增长领域，以满足对其数据业务（如SIEM解决方案）产品的强劲需求。  
###   
### 8. Cloudflare 提升防御能力，应对未来量子安全威胁  
###   
  
Cloudflare 近日宣布，其零信任网络访问（Zero Trust Network Access，ZTNA）解决方案已全面支持后量子密码学（Post-Quantum Cryptography），为企业提供端到端的量子安全连接。  
###   
### 9. 2028年中国网络安全市场规模将超170亿美元，五年复合增长率9.2%  
###   
  
IDC预测，中国网络安全市场规模从2023年的110亿美元增长至2028年的171亿美元，五年复合增长率为9.2%。  
###   
### 10. 上下文合规攻击成功突破多数主流AI模型  
###   
  
一种名为上下文合规攻击（Context Compliance Attack，CCA）的新方法，出乎意料地简单，却能够绕过大多数主流AI系统的安全防护。  
  
  
**一周好文共读**  
  
  
### 1. 不会有人2025了还不会反弹shell吧？让你的反弹shell从0到1！  
  
本文  
从服务器开始讲，讲如何搭建服务器反弹  
shell  
，为什么要搭建服务器，下载反弹  
shell  
的命令，如何避免踩坑，什么是正向反向连接，如何通过  
python  
、  
java  
进行连接，数据包反弹  
shell  
用什么命令，Linux和Windows差别。  
  
  
![1742470879_67dbfedfd502f0a8c9389.png!small?1742470880873](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38XwTgRA48WDosoh2GoRypxIH0tRrSNHBwxGPgC46icsuYsPNDRNgToS9RxLefyD6Ysic08oGSfuPdw/640?wx_fmt=jpeg&from=appmsg "")  
  
### 2. 本地部署deepseek风险？部署工具ollama任意文件读取漏洞超详细分析  
  
近日，DeepSeek 爆火，大部分用户都选择使用 Ollama 在本地搭建 DeepSeek 以使用高效、便捷的 AI 模型。然而，随着 Ollama 在本地大规模应用，其安全性问题也逐渐引起关注。鉴于此，本文深入研究 Ollama 相关的潜在漏洞，探讨其在本地部署环境下可能面临的安全风险。  
  
  
![1742470900_67dbfef4a173e8888e0d7.png!small?1742470901504](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38XwTgRA48WDosoh2GoRypxA8ajb0LpD3tLxGgRpqJeGZibDo6tgxqic25l0tLfrMrrP1hTS4Ej9Zfw/640?wx_fmt=jpeg&from=appmsg "")  
  
### 3. API安全|深度解析与AI赋能攻防实践  
  
现代Web应用广泛采用前后端分离架构（如Tomcat+Nginx），API作为核心通信桥梁，其安全性直接影响整体系统的防护能力，也因此成为攻击者重点目标。常见攻击包括未授权访问、数据泄露和注入攻击，而随着AI技术的发展，API攻防对抗已进入智能化新阶段。  
  
  
![1742470930_67dbff124038a01733115.png!small?1742470930920](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38XwTgRA48WDosoh2GoRypxYBUliaJFUfBKsGPp2ia3KpZRtuOicleb8ZBx1wZ5UlCN3d33e1WeZCd7A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif "")  
  
