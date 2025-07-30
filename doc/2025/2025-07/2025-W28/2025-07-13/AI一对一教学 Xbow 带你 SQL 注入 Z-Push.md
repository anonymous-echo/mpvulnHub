> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODI1ODgzOA==&mid=2247507185&idx=1&sn=e6ecbaf28027cefa944391486187a940

#  AI一对一教学: Xbow 带你 SQL 注入 Z-Push  
原创 一个不正经的黑客  一个不正经的黑客   2025-07-13 04:35  
  
   
  
# AI 一对一教学: Xbow 带你 SQL 注入 Z-Push  
## 前言  
  
最近一直在关注 xbow 的动态，对比其他 SRC 或者国内的思路分享，Xbow 分享出来的实战漏洞文章简直就是一对一教学加完整思考链路的技术分享，不可多得，令人为之痴迷。  
  
当然目前也看到部分国内实验室发表的关于XBOW的分析文章，提到 xbow 目前存在部分局限性，真实效果可能没有那么夸张。  
  
但 AI 可怕之处就在于它能学习  
各种漏洞思路  
并变形超越以及 24H 的不间断攻击大范围目标，而这恰恰是人类的局限，AI 是没有极限的。  
  
从国内安全建设 AI 热潮化，不难看出，屁股决定行动，AI 确实有巨大的潜力，下面让我们一起来学习下吧！  
## 正文  
### 场景铺设：一次正确方向上的 Z‑Push 发现  
  
XBOW 的探索始于一台表面看似无害的 Z‑Push ActiveSync 服务器，安静地驻留于互联网某处。  
  
对于不熟悉的人来说，Z‑Push 是 Microsoft ActiveSync 协议的开源实现，常用于与移动设备同步电子邮件、联系人和日历。  
  
首页上自豪地标注着版本 2.4.4+0，同时显示着熟悉的 “AuthenticationRequiredException” 提示，面对未授权访问者显得十分友好。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMohWwdaBd24WOMsY1M0WLmypjuVLuu5zf7ia1vaRziadQQSbUDBCgr2I9UnMTn1DWY6JIp2JdhtpZPA/640?wx_fmt=png&from=appmsg "")  
  
乍一看，这似乎是一次普通的企业部署，没有什么特别值得注意的地方。服务器配置妥当，启用了身份验证机制，各个端点基本都会返回预期的 401 Unauthorized 响应。  
  
不过，正如每位优秀渗透测试人员所知，通常最平凡的目标，反而蕴含着最有趣的惊喜。  
### 绘制侦察图谱  
  
XBOW 开始对目标服务器进行系统性探索，有条不紊地探测各个端点并绘制服务器结构图：  
- • 主 ActiveSync 端点位于 /Microsoft-Server-ActiveSync  
  
- • 存在标准的 Z‑Push 文件，如 index.php 和 config.php  
  
- • 受限目录（如 /lib/、/include/、/vendor/）均返回 403 Forbidden  
  
- • 配置客户端的 autodiscover 机制  
  
整体来看，系统似乎严密封闭。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMohWwdaBd24WOMsY1M0WLmyomLEnKQlSyuXLDA6u5uxrhkq0cBianicdooTgFEib8hMKB14WFKeEMrSA/640?wx_fmt=png&from=appmsg "")  
  
针对 URL 参数、POST 数据以及各种 HTTP 请求头的多次 SQL 注入尝试，均只得到一致的响应时间，且未出现明显报错信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMohWwdaBd24WOMsY1M0WLmyGmnibJG9SJXtVjpQpgiaWnkAcialN2jricnmXrIXmR1XHicsnd1VT0CDe0g/640?wx_fmt=png&from=appmsg "")  
### 当常规攻击失效时  
  
XBOW 对各种攻击向量进行了全面测试：  
- • 在 URL 参数中注入经典 SQL payload  
  
- • 使用恶意数据测试 POST 请求体  
  
- • 发送针对 ActiveSync 协议的 XML 载荷  
  
- • 利用可能被后端处理的自定义 HTTP 头  
  
- • 针对 MySQL、PostgreSQL 及其他数据库引擎尝试不同 SQL 语法  
  
然而，每次尝试都以相同令人沮丧的结果告终：无论 payload 如何，响应时间始终稳定在约 0.6–0.7 秒。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMohWwdaBd24WOMsY1M0WLmy4fPiccAD1wRBCAzqibsq2TjkN8N3c1Zwf0R7BW4qwbQ2siaIxQtoCszWg/640?wx_fmt=png&from=appmsg "")  
  
服务器似乎铁壁防御，几乎以一种嘲讽的“一成不变”回馈 XBOW 的每一次进攻。  
### 突破时刻：有时你需要照照镜子  
  
转折点出现在 XBOW 把重点转移到认证机制本身。  
  
此前它不断轰击各类端点和参数，却忽视了唯一未充分检验的地方：Basic 认证头中的用户名字段。  
  
当 XBOW 在 Basic Authentication 的用户名位置注入 admin'; SELECT pg_sleep(5) -- 时，发生了有趣的现象：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMohWwdaBd24WOMsY1M0WLmyeo3mnibPhFYdER9gvRuH8udMlicmicMdV1qbBQo8oPMUL9xDeCib4WpNng/640?wx_fmt=png&from=appmsg "")  
  
  
尽管数据库执行的是 5 秒延时命令，响应却接近 8 秒！正是这一刻的观察让 XBOW 豁然开朗：认证后端存在 SQL 注入漏洞，并且运行的是 PostgreSQL 数据库 。  
### 与超时赛跑  
  
确认漏洞本身也是一道难题。虽然 XBOW 的测试清楚地表明存在 SQL 注入（响应时间会与 sleep 指令的延时成比例增长），但它所使用的 check-sqli 验证工具在时延阈值与超时设置方面有自己的判断标准。  
  
XBOW 必须精心平衡以下关键因素：  
- • sleep 时间足够长，以确保统计意义  
  
- • 响应时间又不能太长，否则验证工具会超时  
  
- • payload 格式要在多次请求中表现稳定可靠  
  
经过多轮迭代与调整，XBOW 找到最佳平衡点：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMohWwdaBd24WOMsY1M0WLmyE7FTzw3bzbiarlUaOGvfVKCQzXNG3XssKubOmgiaLpyqrQuGB1hYvZicQ/640?wx_fmt=png&from=appmsg "")  
  
如果你想深入了解 XBOW 的验证器（validators），可以参加 Brendan Dolan‑Gavitt 在 BlackHat USA 2025 上的报告了解更多。  
### 结语：压力之下，保持冷静  
  
在确认漏洞存在后，后续的利用工作由另一位研究人员接手，成功提取了数据库名称和版本信息。该漏洞通过 HackerOne 向客户报告，并迅速获得响应和漏洞奖励。  
  
这次 SQL 注入漏洞的发现提醒我们：即便是成熟、广泛部署的软件，也可能潜藏那些隐蔽的缺陷，而揭示这些问题，往往需要耐心、坚持和系统化的方法。  
  
下次当你面对一个看似固若金汤的目标时，请记住：漏洞并不总藏在显眼之处。  
  
有时，你需要回过头看看根基——认证机制本身，才能找到那条足以摧毁整堵墙的裂缝。  
  
保持冷静，保持执着，祝你狩猎愉快！  
  
XBOW 将继续在各类目标中挖掘与验证漏洞，融合 AI 驱动的分析技术与严谨的验证方法。  
  
如你对技术细节和漏洞研究感兴趣，欢迎持续关注我们在网络安全世界的冒险旅程。  
## 漏洞点评  
  
SQL 注入漏洞出现的存因非常多，这个漏洞如果交给扫描器，不一定能扫出来——因为 Basic 认证常被 base64 编码，扫描器根本不会重点关注用户名字段。  
  
XBOW 的厉害之处在于它极具“拟人操作”特点，不厌其烦地进行大量精细、具备合理逻辑的尝试，而不是像扫描器那样无脑 FUZZ、对接口打上万次请求。  
  
很久以前，大家都认为顶级实战白帽难以被工具替代，因其灵活判断和上下文理解能力。但如今，我们会发现许多“名列前茅”的白帽，其实也是靠刷量而非深入分析各类型漏洞拿到高分排名的（单洞奖金除外）。  
  
目前，业界普遍认为 AI 在逻辑漏洞挖掘上仍有局限——但我坚信，只要 AI 实现“连续操作能力”，并训练于大量逻辑漏洞案例的知识库，它在逻辑漏洞发现方面将展现“恐怖的挖掘能力”。  
  
原因是挖掘逻辑漏洞的本质核心是“细心 + 上下文关联思考”，而这是 AI 的强项！  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMohWwdaBd24WOMsY1M0WLmy12nzm04puuEcMIFHh5IpluQryKSH06mib9B9qnBwHKu9YoYlres4iaug/640?wx_fmt=png&from=appmsg "")  
  
