> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0MDYwMjE3OQ==&mid=2247486896&idx=1&sn=43defdb17bf801bce12e5cc72250945f

#  10 米内就能窃听你的耳机！知名音频芯片曝漏洞，索尼、Bose 等大牌耳机受影响  
原创 HackerNews  安全威胁纵横   2025-07-02 08:03  
  
黑客在蓝牙范围内可监视数百万耳机用户。**研究人员在索尼、Bose、Marshall、Jabra、JBL、拜亚动力等知名品牌，以及使用Airoha Systems芯片的其他设备中，发现了重大安全漏洞。**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok8FsaZqg4zxf4tXPIwEDFgvqxaoGr4yyLaQgWxBZ31ecYYYibxSd3AoruQA7TRyJV35hlxkWTUAp1avT3pe1XA/640?wx_fmt=jpeg "")  
  
   
  
德国网络安全公司ERNW披露，这些漏洞影响了数十款知名耳机型号，包括市场上最好的降噪耳机。**研究人员警告称，在大多数情况下，攻击者无需身份验证或配对，仅需处于蓝牙信号范围内，即可完全接管耳机。**  
  
黑客可利用这些漏洞实时监听用户、劫持设备间的信任关系，甚至冒充耳机向手机发送恶意指令（如拨打电话、访问通讯录），还能提取联系人信息并重写固件以植入恶意代码。研究人员表示：“我们已证明可轻易监听耳机麦克风当前录制的内容。”用户可能仅会注意到蓝牙连接短暂中断，因为耳机通常仅支持单一连接。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok8FsaZqg4zIhuIBaTDicZxhXfX1XBxQJiakZaQ3OPbNcAjXg4aHviaFvI7Cjlo5micHgl5Ua4MQeicVmoI0ZyriasEg/640?wx_fmt=png&from=appmsg "")  
  
图源insinuator.net.  
  
  
所有未修复的Airoha Systems芯片（SoC）设备均受影响。Airoha是蓝牙音频芯片的主要供应商，尤其在真无线立体声耳机领域。蓝牙芯片暴露了强大的自定义协议，允许通过读写RAM或闪存来操控设备，缺少身份验证使攻击者无需配对即可使用该协议。由于大多数设备尚未修复，研究人员未披露过多细节、概念验证代码或暴露协议的名称。  
  
SoC被用于耳机、耳塞、适配器、音箱和无线麦克风等设备，但全面排查和识别所有受影响产品难度较大。  
  
  
部分受影响的设备包括：  
- 索尼：WH-1000XM4/5/6、WH-CH520、WH-XB910N等  
  
- Marshall：ACTON III、MAJOR V等  
  
- Bose：QuietComfort消噪耳塞  
  
- 拜亚动力：Amiron 300  
  
- EarisMax：Bluetooth Auracast Sender  
  
- Jabra：Elite 8 Active  
  
- JBL：Endurance Race 2、Live Buds 3  
  
- Jlab：Epic Air Sport ANC  
  
- MoerLabs：EchoBeatz  
  
- Teufel：Tatws2  
  
“同款蓝牙SoC被用于数十或数百种不同产品，通常在不同品牌下销售。”部分厂商未披露所用芯片，增加了识别所有受影响设备的难度。  
  
主要漏洞被标记为“自定义协议的关键能力”，编号为CVE-2025-20702。另外两个漏洞CVE-2025-20700和CVE-2025-20701，均涉及蓝牙协议中缺失的身份验证。研究人员后续会发布详细信息。  
  
用户需等待厂商修复设备。目前耳机用户几乎无法防范攻击者的窃听或操控。ERNW研究人员表示：“终端用户需要更新耳机固件，但在此之前，必须有可用的补丁。”尽管Airoha已于6月初向厂商提供修复SDK，但不同设备制造商分发固件更新的速度未知，部分产品可能永远无法获得修复。研究人员警告：“目前我们尚未知晓任何已修复的固件发布。”即使存在补丁，也不是所有设备制造商都会推送更新，尤其是对于低成本或已停产的产品。  
  
幸运的是，现实攻击门槛较高：**攻击者必须非常接近用户，通常在10米内，因为蓝牙仅适用于短距离。攻击还需高技术能力以不被察觉。这类攻击最可能针对高价值个体，如记者、外交官、政治活动家、敏感行业从业者和其他VIP。**  
这些用户建议在补丁发布前，解除耳机与手机的配对。  
  
  
  
转载请注明出处@安全威胁纵横，封面来源于pixabay；  
  
消息来源：https://cybernews.com/security/millions-of-headphones-vulnerable-to-bluetooth-hacks/  
  
  
  
  
 更多网络安全视频，请关注视频号“知道创宇404实验室”  
  
  
  
