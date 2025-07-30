> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3OTYxODQxNg==&mid=2247486310&idx=1&sn=ef99da72a2b3f6bbfe3f973f32c8f4a3

#  暗战揭秘：伊朗系APT组织BladedFeline的隐秘攻击网络  
原创 紫队  紫队安全研究   2025-06-21 04:00  
  
**大家好，我是紫队安全研究。建议大家把公众号“紫队安全研究”设为星标，否则可能就无法及时看到啦！因为公众号只对常读和星标的公众号才能大图推送。操作方法：先点击上面的“紫队安全研究”，然后点击右上角的【...】,然后点击【设为星标】即可。**  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RC5DX3dxrbdI78U5mj7tBEyqvaNJlicrhI4yic61GK2joLEficw2kd5d9qg1uJC6JEI1m9vpxHpKibyg/640?wx_fmt=jpeg "")  
  
  
 前言：中东政治漩涡中的数字间谍    
  
  
在中东地缘政治的暗战中，一个与伊朗关联的神秘APT组织正悄然编织着数字监控网络。ESET最新研究发现，BladedFeline自2017年起持续渗透库尔德地区政府（KRG）及伊拉克政府官员系统，其使用的Whisper后门与PrimeCache恶意模块，与伊朗老牌APT组织OilRig的工具链高度同源。这场跨越八年的网络间谍活动，不仅暴露了中东政要的通信安全漏洞，更揭示了国家支持型攻击的代际进化。    
  
  
  
 🐾 BladedFeline：OilRig的"暗影分支"    
  
  
 ▶ 组织溯源：从神话到现实的攻击矩阵    
  
名称由来：得名于伊朗民间传说中的"半蛇半女人"神兽Shahmaran，其标志性后门以此命名，体现文化符号与恶意工具的结合；    
  
血缘关系：ESET以中等置信度判断其为OilRig（APT34）的子群，代码层面与OilRig的RDAT后门共享加密逻辑与命令执行模块；    
  
目标画像：专注中东政要与能源领域，2017年首次攻陷KRG系统，2023年扩展至伊拉克政府及乌兹别克斯坦电信商。    
  
  
 ▶ 八年攻击时间线（2017-2024）    
  
```mermaid  
  
timeline  
  
    2017-09 : VideoSRV反向shell植入KRG系统  
  
    2018-01 : RDAT后门长期驻留  
  
    2023-02 : Shahmaran后门首次现身  
  
    2024-01 : Whisper邮件后门部署  
  
    2024-02 : PrimeCache IIS模块渗透伊拉克政府  
  
```    
  
  
  
 ⚙️ 武器库解析：从窃密到持久控制    
  
  
 ▶ Whisper后门：用邮件编织的间谍网络    
  
通信诡术：    
  
  通过攻陷的Exchange邮箱发送加密附件指令，以"PMO"为邮件主题标识符，将命令拆解为多请求传输（先传参数再执行），规避邮件网关检测；    
  
伪装技巧：    
  
  配置文件base64编码，编译时间戳伪造至2080年后，使用Costura打包DLL避免依赖检测。    
  
  
 ▶ PrimeCache：IIS服务器中的幽灵模块    
  
潜伏机制：    
  
  作为IIS原生模块，通过Cookie头中的`F=<command_ID>,<param>`格式接收指令，支持文件读写、命令执行等操作；    
  
技术同源性：    
  
  与OilRig的RDAT后门共享Crypto++加密库，使用相同正则表达式解析命令参数，暴露开发团队重叠痕迹。    
  
  
 ▶ 辅助工具链：多维度渗透矩阵    
  
| 工具名称   | 功能定位                 | 攻击场景                          |    
  
|------------|--------------------------|-----------------------------------|    
  
| Laret/Pinar | 反向隧道                 | 建立SSH端口转发，维持内网通信      |    
  
| Slippery Snakelet | Python轻量级后门         | 远程执行命令与文件传输            |    
  
| Flog       | 网页后门                 | 伊拉克政府网站权限维持            |    
  
  
  
 ⚔️ 实战案例：政要系统沦陷全过程    
  
  
 ▶ 库尔德官员的"邮件陷阱"    
  
1. 鱼叉钓鱼：伪造外交合作邮件诱导点击，下载伪装成PDF的Whisper Protocol（Protocol.pdf.exe）；    
  
2. 权限提升：通过Shahmaran后门修改启动项，实现系统重启持久化；    
  
3. 情报收割：Whisper定期读取Outlook邮件，将加密后的政要通信发往伊朗控制的邮箱。    
  
  
 ▶ 伊拉克政府的"IIS沦陷"    
  
漏洞利用：攻陷互联网-facing服务器，部署Flog webshell获取初始权限；    
  
纵深渗透：上传PrimeCache模块至IIS目录，通过篡改HTTP请求窃取政务系统数据；    
  
数据外发：利用Pinar隧道将敏感文件加密传输至境外服务器，2024年2月曾窃取石油贸易协议。    
  
  
  
 ⚠️ 威胁本质：地缘政治的数字投射    
  
  
 ▶ 情报价值链条    
  
战略目标：监控库尔德与西方的外交互动，获取伊拉克石油资源分配情报，服务伊朗地区影响力扩张；    
  
技术试验场：在中东复杂网络环境中测试新型工具（如Whisper的邮件通信模式），为全球行动积累经验。    
  
  
 ▶ 防御盲区警示    
  
邮件网关失效：Whisper使用合法邮件协议通信，传统反垃圾邮件系统难以识别；    
  
IIS模块信任危机：PrimeCache利用管理员对IIS原生组件的信任，绕过90%的Web应用防火墙。    
  
  
  
 🛡️ 防御指南：政企级反制策略    
  
  
 ▶ 企业应急响应    
  
1. IIS深度审计：    
  
   扫描所有IIS模块哈希值，对比PrimeCache特征（SHA-1: 562E1678EC8FDC1D83A3F73EB511A6DDA08F3B3D）；    
  
   禁用非必要的IIS扩展，限制模块加载权限。    
  
2. 邮件安全强化：    
  
   启用Exchange邮件附件沙箱检测，阻断含Whisper特征的加密附件；    
  
   对政要邮箱启用多因素认证，监控异常IP登录（如伊朗IP段178.209.0.0/16）。    
  
  
 ▶ 个人防护要点    
  
文件校验：对下载的PDF文件右键查看属性，警惕名称异常的可执行文件（如Protocol.pdf.exe）；    
  
通信加密：使用Proton Mail等端到端加密邮件服务，避免通过公共邮箱传输敏感信息。    
  
  
  
 🔚 结语：当传说成为现实威胁    
  
  
BladedFeline的活动揭示了一个趋势：国家支持的APT组织正从单一技术攻击转向“文化符号+模块化工具+地缘目标”的精准打击。对于中东政要而言，一次邮件点击可能泄露的不仅是个人隐私，更是地区权力博弈的关键筹码。    
  
****  
****  
**加入知识星球，可继续阅读**  
  
**一、"全球高级持续威胁：网络世界的隐形战争"，总共26章，为你带来体系化认识APT，欢迎感兴趣的朋友****入圈交流。**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/sUKKZDdVP8RRAic0GwkHmSw2QZes8kK1AfysU8oPBib56yJpTWxmMuHRQBk3DHtibEASDuO7FTia8jIpeYtMFicBy5A/640?wx_fmt=jpeg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8Sm53HIUuI9RNR5Vpk1TWmpt3dw7icrMOJchapl0qTHsxVnXHyicBmV2kNlgpt3WLGLgdBJKrWiaUGicw/640?wx_fmt=png&from=appmsg "")  
  
**二、"Deep****Seek：APT攻击模拟的新利器"，为你带来APT攻击的新思路。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/sUKKZDdVP8SmEmOb6eVreW81Qh8DCAQvT2jLpI7JoYFWHibP6wCCI2AicqKAgbc4GzoAafviavpdxGjBqGrs1nlibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**喜欢文章的朋友动动发财手点赞、转发、赞赏，你的每一次认可，都是我继续前进的动力。**  
  
  
  
  
