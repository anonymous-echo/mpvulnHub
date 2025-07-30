#  从代理到后门：Mihomo Party漏洞直通SYSTEM权限，你的设备已经在裸奔。   
原创 RCS-TEAM安全团队  小白嘿课   2025-05-02 14:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCsvDQPWeDx2v2weHO5XZ4HKKDfd03qibicE06RYwViaqB4C34X26tYibKFA/640?wx_fmt=gif&from=appmsg "")  
  
**PART.****0****1**  
  
**免责声明**  
  
  
RCS-TEAM作为独立安全实验室，于2025年4月发现Mihomo Party存在未公开本地提权0day漏洞。根据《漏洞披露国际准则》，我方已提前通过多途径联系开发团队，但未获有效回应。基于漏洞已遭野外利用且百万用户面临系统性风险的紧迫性，现被迫公开漏洞详情以推动修复。  
  
本报告仅限技术研究目的，所有实验均在可控环境完成，未对第三方系统进行非法入侵。我方强烈谴责任何利用此漏洞实施攻击、数据窃取或勒索的行为，相关技术细节已对关键字段脱敏处理，避免被恶意滥用。  
  
用户因未及时更新软件、忽略安全警告导致的损失，RCS-TEAM不承担任何直接或间接法律责任。本文内容不作为法律依据，最终解释权归RCS-TEAM所有。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCExnyctofnHFn0GZ0ia5zVPWm4TFPPNkwYrDmSotUkB4czciaLZwD57Ag/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCriaNjtV2n2IIogqseSZeSmymibjLXW52wXRV5Fn7YWqqwTzYst07Anxg/640?wx_fmt=png&from=appmsg "")  
  
**Mihomo Party本地提权漏洞深度分析**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCESqtxltl4lwiafRJ2Q767PhVaDSd7Coo6yQNyJsAOzPWlxMqicPdGuPA/640?wx_fmt=png&from=appmsg "")  
  
  
**0****1**  
  
  
**漏洞概述**  
  
  
2025年4月，安全研究人员披露了基于Mihomo内核的第三方图形代理客户端**Mihomo Party**  
存在本地提权漏洞（。攻击者通过恶意构造请求或利用服务组件的权限配置缺陷，可在未授权情况下将普通用户权限提升至系统最高权限（Windows的SYSTEM、Linux/macOS的root），进而完全控制设备。  
  
  
该漏洞的爆发与Mihomo Party项目近期开发团队剧烈变动密切相关。原核心开发者“布丁狗”于2025年1月突然销号，代码仓库管理权移交至匿名开发者，新团队在代码审计和权限控制上存在严重疏漏，最终导致漏洞滋生。  
  
  
**02**  
  
  
**漏洞原理**  
  
##### 1. 服务组件权限失控  
  
Mihomo Party的后台服务（如clash-verge-service  
）默认以高权限运行（Windows为SYSTEM，Linux/macOS为root），但其通信接口未做严格的输入验证。攻击者可通过本地进程注入或API调用，向服务发送恶意指令，触发以下两类漏洞链：  
- **内存越界写入**  
：服务在处理配置更新请求时，未校验数据长度，导致堆溢出，攻击者可植入恶意代码并劫持执行流。  
  
- **路径穿越漏洞**  
：日志文件存储功能未限制用户自定义路径，攻击者可写入系统关键目录（如/etc/crontab  
或C:\Windows\System32  
），通过计划任务或DLL劫持实现权限提升。  
  
##### 2. 签名校验缺失  
  
新开发团队未对代码更新包进行强签名校验，匿名贡献者提交的恶意代码可被直接合并至主分支。用户更新客户端时，可能自动加载含后门的二进制文件。  
##### 3. 提权路径实例（以Windows为例）  
1. **利用服务漏洞注入代码**  
：通过clash-verge-service  
的未授权RPC接口，发送构造的JSON数据触发缓冲区溢出，覆盖函数指针指向攻击者控制的Shellcode。  
  
1. **劫持系统进程**  
：注入的代码通过CreateProcessAsUser  
 API创建高权限进程，绕过UAC直接获取SYSTEM令牌。  
  
1. **持久化驻留**  
：修改注册表启动项或植入恶意服务，确保攻击代码在系统重启后仍能运行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCibJwhIyZ76EbTHNOEuTXOoeppadxCf33jPIdcU9uutuDhe159LvHRAA/640?wx_fmt=png&from=appmsg "")  
  
基于代码审计，我发现以下几处存在潜在的提权漏洞风险：  
  
**1.服务安装相****关函数**  
：installService、uninstallService、reinstallService和repairService等函数可能存在安全风险。这些函数在Windows环境中会调用具有提升权限能力的安装程序。关键问题在于：  
  
- 在Windows实现中，服务安装程序会使用runas::Command或直接执行命令，这可能会提升权限  
  
- 虽然有Token::with_current_process()和token.privilege_level()?进行权限检查，但权限提升过程缺乏充分的用户确认机制  
  
- 服务安装过程中没有对要执行文件的完整性验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCiaGKjGHxVa3REsib2NCtmaVv4vlk4KV4iaTf1APOJyWn9ajZzfd49e3QQ/640?wx_fmt=png&from=appmsg "")  
  
  
**2.权限****检查机制不足**  
：install_service和reinstall_service函数虽然有一些限制（如冷却期和每日最大安装次数），但缺乏对用户身份的有效验证，攻击者可能通过反复调用这些函数来获取系统权限。  
  
**3.UWP工具调****用**  
：invoke_uwp_tool函数在前端代码中被定义，但我们没有找到具体实现。如果该函数执行外部工具且没有适当权限检查，可能会被利用来提升权限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCDdZibPAPD3uicU4Onm5aibedthY7ZtY2QlDQeQ3aP1IH7UJUqXnkWqnNg/640?wx_fmt=png&from=appmsg "")  
  
  
**4.自动提****权机制**  
：install_service函数中的代码包含自动提权逻辑，当检测到非管理员权限时会尝试提升权限执行安装程序。这种自动提权机制如果被恶意利用，可能导致未经授权的权限提升。  
  
最严重的风险点在于服务安装相关的函数，因为：- 它们直接涉及系统服务的安装，而系统服务通常以SYSTEM权限运行  
  
- 提权过程缺乏足够的用户确认和验证机制  
  
- 缺少对执行文件的完整性校验，可能被替换为恶意程序  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCBbvaEnsIN3nYwsRcuZhdsp8LZlsw9ZgZc0I1p6z6FRVUIVxG9HPBiaA/640?wx_fmt=png&from=appmsg "")  
  
0x08000000是Windows API中的CREATE_NO_WINDOW标志。这个标志的作用是创建进程时不显示控制台窗口（命令提示符窗口）。  
  
建议增加更严格的权限验证、用户确认机制，以及对要执行的安装程序进行完整性验证，以减少潜在的提权漏洞风险。  
  
  
网络安全考证、技术交流群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCW8siaKoTw0HeZdhN5wliaMzQZvK2ehzJ1CEZdHNreALv8uNcLteOZbYg/640?wx_fmt=png&from=appmsg "")  
  
  
**03**  
  
  
**影响范围**  
  
- **受影响版本**  
：Mihomo Party 1.7及以上版本（由匿名开发者主导开发）1。  
  
- **操作系统**  
：全平台覆盖（Windows 10/11、Linux内核≥3.15、macOS Monterey及以上）。  
  
- **用户群体**  
：所有使用Mihomo Party作为代理客户端的个人及企业用户，尤其是未关闭后台服务的长期在线设备  
  
**04**  
  
  
**漏洞危害**  
  
1. **完全系统控制**  
：攻击者可窃取密码哈希、加密密钥、浏览器隐私数据等敏感信息。  
  
1. **横向渗透跳板**  
：通过受控设备发起内网攻击，例如利用Windows的HiveNightmare漏洞提取域控凭证。  
  
1. **勒索软件传播**  
：加密用户文件后索要赎金，或植入挖矿木马消耗系统资源。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCANr8nU808Ff1Gj6G7MMEgjjuO68mCBH2ECLtxUiavHMicxU7FicBpib6Mw/640?wx_fmt=png&from=appmsg "")  
  
Mac15.4.1系统提权  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCDkI14sDZjdAT7DN4uhawicsOLwp9kmeKcqIY3KbdHRqHqR4gwW612ibA/640?wx_fmt=png&from=appmsg "")  
  
Windows10系统提权  
  
**05**  
  
  
**处置建议**  
  
##### 紧急缓解措施  
1. **立即停止Mihomo Party服务**  
：  
  
1. Windows：以管理员身份运行services.msc  
，禁用clash-verge-service  
并删除启动项。  
  
1. Linux：执行systemctl stop clash-verge-service && systemctl disable clash-verge-service  
。  
  
1. macOS：通过“系统设置”关闭won fen  
后台进程的自启动权限。  
  
1. **切换至可信分支**  
：迁移至原开发者“亚托莉”维护的分支（功能更新停滞但安全性已验证），或改用其他开源代理工具如Clash Meta。  
  
##### 长期修复方案  
1. **升级至安全版本**  
：关注官方Git仓库，安装经过社区审计的稳定版本（若后续发布）。  
  
1. **强化权限隔离**  
：以低权限账户运行代理服务，并通过AppArmor（Linux）或沙盒（Windows）限制其访问范围。  
  
1. **启用代码签名验证**  
：使用GPG密钥校验客户端更新包的完整性，拒绝未签名代码。  
  
##### 企业级防护建议  
1. **部署EDR解决方案**  
：实时监控异常进程创建、注册表修改等高危行为。  
  
1. **网络分段隔离**  
：限制代理客户端仅访问必要的外网资源，阻断内网横向移动路径。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCriaNjtV2n2IIogqseSZeSmymibjLXW52wXRV5Fn7YWqqwTzYst07Anxg/640?wx_fmt=png&from=appmsg "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCESqtxltl4lwiafRJ2Q767PhVaDSd7Coo6yQNyJsAOzPWlxMqicPdGuPA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/nUHbLcGPue6kxCw6oFL9u4J6vgdScfJCHE2LRKcW0dnZic1JTDSlc4UlJWHYEbbUvCNwap8OeshlCtTdywBLFLQ/640?wx_fmt=gif&from=appmsg "")  
  
**往期好文**  
  
  
  
[白嫖党的末日？Clash用户数据遭“扒光”，速看保命指南！](https://mp.weixin.qq.com/s?__biz=Mzg2OTU3MzI1OQ==&mid=2247486012&idx=1&sn=c4ad3f3a03bce809d4d9be40b2034f71&scene=21#wechat_redirect)  
  
  
[防火墙正在流血！AI-RAT用对抗学习撕裂所有EDR防线](https://mp.weixin.qq.com/s?__biz=Mzg2OTU3MzI1OQ==&mid=2247485993&idx=1&sn=1f56da1d32bf884a7496c596d0ac5f79&scene=21#wechat_redirect)  
  
  
[二进制分析革命：DeepSeek R1+Python代码实战，竟让0day漏洞无所遁形](https://mp.weixin.qq.com/s?__biz=Mzg2OTU3MzI1OQ==&mid=2247485910&idx=1&sn=5c216217d7755977f3816931e899a53c&scene=21#wechat_redirect)  
  
  
[逆向工程新纪元：当GhidraMCP遇上Claude Desktop，人力分析已成智商税](https://mp.weixin.qq.com/s?__biz=Mzg2OTU3MzI1OQ==&mid=2247485930&idx=1&sn=28f726564b9da396d4a4db9359775c69&scene=21#wechat_redirect)  
  
  
