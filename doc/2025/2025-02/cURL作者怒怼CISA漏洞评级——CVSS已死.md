#  cURL作者怒怼CISA漏洞评级——CVSS已死   
原创 玄月调查小组  玄月调查小组   2025-02-04 02:05  
  
当全球装机200亿次的cURL工具面临  
严重漏洞  
危机，当冷门漏洞撞上CISA的「暴力量化」，当开源大佬被迫与CVSS漏洞评分体系正面对刚。  
  
今天我们来聊一个让开发者们“血压飙升”的话题——漏洞评级，以及一位开源硬核大佬的反击。  
## CVSS是什么？  
  
CVSS[1]  
（Common Vulnerability Scoring System，通用漏洞评分系统）是一个开放的标准，用于  
评估软件中安全漏洞的严重性  
。它提供了一个量化的方法，帮助组织优先处理漏洞管理流程，并确定响应的优先级。  
  
CVSS听起来像是一套精密算法，能像天气预报一样告诉你漏洞的“杀伤力”。但真相是：它更像一场**“在线算命”**  
。  
  
按照维基百科的说法，CVSS是通过勾选几个复选框（比如“攻击复杂度”“用户交互需求”），然后“生成”**一个0-10的分数。理论上，这个分数能帮企业判断漏洞的严重性。但现实呢？“理论很丰满，现实很骨感。”**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aYef9qMYLnLkiaRZcia2yTicFCS7YI7FSlibJE3pepHJH9b5cNLjzULnGqzw1uTibkhibGAaMGWCEhuTgpxKvFDyo86Q/640?wx_fmt=png&from=appmsg "")  
  
NVD的CVSS在线计算器页面  
  
举个栗子🌰：假设你像**Daniel Stenberg**  
一样，开发了全球装机量超200亿次的网络传输工具**cURL**  
，却发现某个漏洞只在某个冷门平台上才能触发。这时CVSS会直接甩出一个高分，理由是“影响网络服务”。  
## cURL之父掀桌：我们不玩CVSS了！  
  
面对CVSS的“一刀切”评分，cURL之父Daniel Stenberg直接掀了桌子：“  
CVSS is dead to us[2]  
”  
  
作为**CNA（CVE编号机构）**  
，cURL可以自主发布漏洞编号，但CVE系统默认每个漏洞必须带CVSS评分。于是当cURL拒绝“算命”时，CISA（网络安全和基础设施安全局）就出手了——他们批量补充分数，结果可想而知：  
- **翻车现场**  
：CVE-2024-11053漏洞，cURL团队评估为**低风险（Low）**  
，但CISA大手一挥，直接标为**9.1分（严重）**  
，安全扫描器疯狂报警。Daniel不得不在周日陪伴家人时紧急提交PR，求CISA“高抬贵手”。最终，分数被改成3.4分，但互联网上已流传起“cURL史诗级漏洞”的传说……  
  
### 为什么CVSS成了“万人嫌”？  
1. **一维评分，多维翻车**  
  
CVSS试图用一个数字概括所有场景，但现实中的漏洞严重性取决于**具体使用环境**  
。比如某个漏洞在默认配置下无害，但在某个魔改版系统中可能被利用。  
  
1. **专家vs键盘侠：谁更懂代码？**  
  
cURL团队由**代码亲爹团**  
组成（毕竟Daniel写了第一行代码），但CISA的评分员可能连cURL的文档都没读过。**“让一个没下过厨的人评价米其林菜品，结果只能是‘报吃’。”**  
  
1. **扫描器的“狂欢”**  
  
许多安全产品靠CVSS分数刷存在感，分数高的漏洞会被标红加粗，甚至触发合同中的“修复倒计时”。于是，开发者们被迫处理“虚假警报”**，甚至间接诱骗用户删除系统组件[3]。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aYef9qMYLnLkiaRZcia2yTicFCS7YI7FSlib3Opjmb25345ibhq0lQEAQZ03pfEQPnRkh58xJRkctEEdlobU3UWGNDw/640?wx_fmt=png&from=appmsg "")  
  
删除系统curl.exe哄骗智障扫描器？cURL之父警告：系统崩了别找我  
## cURL的叛逆：我们跳过CVSS  
  
既然CVSS不靠谱，Daniel带领团队决定自己搞事情：他们将漏洞分为低、中、高、严重四级，理由很硬核：  
- **“我们比计算器更懂代码”**  
：cURL团队对代码逻辑和使用场景了如指掌，可以更好的评估和设置严重性。  
  
## CVSS的未来：是改革还是埋葬？  
  
尽管Daniel在CNA圈内呼吁**“取消CVSS强制评分”**  
，但现实很骨感：  
- **利益链难撼动**  
：安全厂商、企业等都依赖CVSS刷存在感；  
  
Daniel的吐槽引发共鸣，**Go语言安全团队**  
也跳出来：“俺们也一样！” 也有人提议用**SSVC**  
、  
EPSS  
等评分框架替代CVSS，但推广之路漫漫。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aYef9qMYLnLkiaRZcia2yTicFCS7YI7FSlibYxpuDiaKdBxl4dVG2c7z21AlkcoNYQdAicM5oKnVOesfrWVUDd4K9Vvw/640?wx_fmt=png&from=appmsg "")  
## 结语：安全不是数字游戏  
  
下次当你看到“严重漏洞警报”时，不妨多问一句：**“这分数是谁打的？TA用过我的代码吗？”**  
  
毕竟，真正的安全不是靠“算命分数”，而是**理解风险、理性应对**  
。  
  
**互动话题**  
：你被漏洞评级坑过吗？你支持开发者夺回漏洞评分权吗？欢迎在评论区吐槽～  
  
👉 关注「玄月调查小组」，解剖硬核技术！  
  
### 参考资料  
  
[1]   
CVSS: https://en.wikipedia.org/wiki/Common_Vulnerability_Scoring_System  
  
[2]   
CVSS is dead to us: https://daniel.haxx.se/blog/2025/01/23/cvss-is-dead-to-us/  
  
[3]   
deleting system32\curl.exe: https://daniel.haxx.se/blog/2023/04/24/deleting-system32curl-exe/  
  
