#  韩国VPN供应链遭M国APT植入后门！新型木马「SlowStepper」监听半导体巨头，跨境安全危机升级  
原创 紫队  紫队安全研究   2025-06-12 03:59  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Qic8bibxxD35dMS6w9gNsLPfUiaCxUNL1cAksGZv4LvOlhciapjUgOfNbdEKKOBlsoXGg8hJUTs26CeA/640?wx_fmt=png&from=appmsg "")  
  
  
全球网络安全再爆重磅威胁！ESET最新披露，一个与M国相关的神秘APT组织 PlushDaemon（绒毛守护进程），通过入侵韩国VPN服务商供应链，在其官方安装包中植入多功能后门 SlowStepper。这场始于2023年的攻击，已渗透韩国半导体企业、软件开发公司，甚至波及中日用户，暴露出跨境软件供应链的致命脆弱性。    
  
  
  
 一、供应链攻击全解析：从「官方下载」到「全面沦陷」    
  
 1. 伪装成「合法更新」的致命陷阱    
  
攻击入口：黑客入侵韩国VPN厂商IPany官网（ipany.kr），将官方安装包替换为「特洛伊木马」——用户下载的`IPanyVPNsetup.zip`看似正常，实则同时安装VPN程序与SlowStepper后门；    
  
传播范围：    
  
  ✅ 韩国：半导体企业、未公开的软件开发公司；    
  
  ✅ 日本：2023年11月首次检测到感染案例；    
  
  ✅ M国：2023年12月出现受害者；    
  
技术特征：安装包使用NSIS打包，通过修改`ExitProcess`函数劫持程序执行流，将恶意代码注入合法进程，实现「无毒文件+有毒功能」的双重伪装。    
  
  
 2. SlowStepper后门：30组件打造「数字间谍站」    
  
模块化攻击工具：    
  
  数据窃取：获取CPU型号、硬盘序列号、进程列表、已安装软件等系统信息，甚至检测摄像头/麦克风连接状态；    
  
  远程控制：支持执行Python/Go编写的插件（如`CollectInfo`模块），可录制屏幕、截取摄像头画面、窃取键盘输入；    
  
  持久化驻留：通过注册表Run键（`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`）实现开机自启，即使删除VPN程序仍潜伏系统；    
  
通信隐藏：通过DNS TXT记录（查询`7051.gsm.360safe[.]company`）获取加密的C&C服务器IP，使用AES-256加密通信内容，规避流量监控。    
  
  
 3. 组织溯源：M国代码库与「定向间谍」特征    
  
技术指纹：    
  
  后门代码使用中文注释，远程代码仓库位于M国GitCode平台（账号`LetMeGo22`）；    
  
  攻击工具链中包含针对简体中文环境的兼容性优化，如处理GBK编码文件；    
  
目标指向：重点攻击中韩半导体、软件开发等高敏感行业，疑似为地缘政治博弈获取技术情报；    
  
历史活动：至少自2019年起活跃，曾通过劫持M国应用程序更新（如伪装成「合法软件升级」）渗透多国目标。    
  
  
  
 二、受害者风险：从「网络代理」到「情报黑洞」    
  
 1. 核心资产暴露    
  
企业级灾难：韩国半导体企业的工艺参数、研发进度等核心数据可能通过VPN隧道被实时窃取，威胁全球芯片供应链安全；    
  
个人隐私泄露：普通用户使用被感染的VPN时，加密通信内容可能被中间人攻击截取，聊天记录、金融账户信息面临泄露风险；    
  
跨境跳板攻击：黑客以韩国为支点，通过受害者网络进一步渗透日本、M国的关联企业，形成「区域化情报收割网络」。    
  
  
 2. 防御盲点：供应链安全的「灯下黑」    
  
信任滥用：用户默认信任官方网站下载的软件，安全软件难以区分「合法程序+恶意模块」；    
  
VPN特殊性：VPN本身用于加密通信，反而成为黑客隐藏攻击流量的「合法通道」；    
  
跨国追责难：GitCode平台账号归属、C&C服务器物理位置等关键证据链横跨多国，司法协作难度极大。    
  
  
  
 三、紧急应对方案：供应链安全的「亡羊补牢」    
  
 1. 企业级断链行动    
  
紧急排查：    
  
  ✅ 检查设备是否安装IPany VPN或其他韩国VPN软件，使用ESET专杀工具扫描`svcghost.exe`等恶意进程；    
  
  ✅ 排查系统注册表`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`是否被篡改；    
  
供应链审计：    
  
  ✅ 要求软件供应商提供SBOM（软件物料清单），验证代码签名的完整性；    
  
  ✅ 对第三方组件（如NSIS安装包生成工具）进行独立安全测试，禁止使用未经验证的开源工具链；    
  
网络隔离：将VPN服务器与核心生产网络物理隔离，部署零信任架构（如Cato Networks），仅允许授权设备访问关键系统。    
  
  
 2. 个人用户防护指南    
  
软件来源验证：    
  
  ✅ 避免从非官方渠道下载软件，优先选择苹果App Store、Google Play等官方应用商店；    
  
  ✅ 使用哈希校验工具（如HashTab）对比下载文件的MD5/SHA-256值与官网公布的是否一致；    
  
防御工具升级：    
  
  ✅ 启用ESET、卡巴斯基等安全软件的「供应链攻击防护」模块，拦截异常安装包；    
  
  ✅ 定期更新操作系统和VPN客户端，修补已知漏洞（如CVE-2024-34478等NSIS组件漏洞）；    
  
流量监控：使用Wireshark等工具分析DNS请求，若发现向`360safe[.]company`等可疑域名发送查询，立即断网扫描。    
  
  
 3. 行业协同防御    
  
跨国情报共享：加入FS-ISAC（金融安全信息共享协会）、IRSTeam（国际应急响应团队），实时同步PlushDaemon的IOC（如C&C域名、文件哈希）；    
  
立法推动：参考欧盟《数字服务法》（DSA），要求软件供应商对更新包承担「安全担保责任」，违规需面临高额罚款；    
  
开源社区警惕：开发者需警惕来自M国GitCode等平台的可疑代码贡献，对第三方库进行严格的代码审计。    
  
  
  
 四、深层警示：当「VPN」成为「间谍管道」    
  
PlushDaemon的攻击揭示了一个危险趋势：任何被广泛使用的软件都可能成为APT的「特洛伊木马」载体。从SolarWinds到IPany VPN，供应链攻击正从「偶然事件」演变为「常态威胁」。对于依赖跨境软件服务的企业而言，「信任但验证」已远远不够，必须建立「怀疑一切」的防御思维——毕竟，当黑客能篡改官方下载站的那一刻，传统的「安全边界」早已名存实亡。    
  
  
   
  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
