> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070639&idx=2&sn=f98a8cececf06db2add503959abb412c

#  【安全圈】PerfektBlue：四项蓝牙协议栈漏洞危及数百万车辆，可被远程执行代码  
 安全圈   2025-07-13 11:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
车载蓝牙  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgvicgOibfJv5FVZticJmXUibrctdyFLaicavc23wRYWPG31aX9cmPS0wb9UsnQVJJ33jWERuGKDypCGWA/640?wx_fmt=png&from=appmsg "")  
  
**事件概述**  
  
PCA Cyber Security（原 PCAutomotive）披露，OpenSynergy 的蓝牙协议栈 BlueSDK 存在 **四个关键安全漏洞**  
，组合利用后可实现远程代码执行（RCE），影响涵盖 **Mercedes-Benz、Volkswagen、Skoda**  
 以及至少一家未公开名称的主机厂（OEM）车型。  
  
此漏洞链统称为 **PerfektBlue**  
，涉及内存破坏与协议处理逻辑缺陷，允许攻击者在目标车辆靠近配对状态下，远程侵入车载信息娱乐系统（IVI）并进一步实现系统控制与横向移动。  
## 漏洞详情（CVE 编号）  
<table><thead><tr><th><section><span leaf="">CVE编号</span></section></th><th><section><span leaf="">描述</span></section></th><th><section><span leaf="">CVSS评分</span></section></th></tr></thead><tbody><tr><td><section><span leaf="">CVE-2024-45434</span></section></td><td><section><span leaf="">AVRCP 服务中的 Use-After-Free</span></section></td><td><section><span leaf="">8.0</span></section></td></tr><tr><td><section><span leaf="">CVE-2024-45431</span></section></td><td><section><span leaf="">L2CAP 通道远程 CID 验证不足</span></section></td><td><section><span leaf="">3.5</span></section></td></tr><tr><td><section><span leaf="">CVE-2024-45433</span></section></td><td><section><span leaf="">RFCOMM 函数终止处理错误</span></section></td><td><section><span leaf="">5.7</span></section></td></tr><tr><td><section><span leaf="">CVE-2024-45432</span></section></td><td><section><span leaf="">RFCOMM 中错误参数调用</span></section></td><td><section><span leaf="">5.7</span></section></td></tr></tbody></table>## 攻击流程概述  
  
攻击者只需在 **5~7 米范围内**  
，利用目标车辆处于**蓝牙配对模式**  
时触发攻击流程：  
1. **配对接入 IVI 系统**  
；  
  
1. **触发内存漏洞链**  
获取 RCE；  
  
1. **访问敏感信息**  
（GPS、麦克风、联系人等）；  
  
1. **条件允许时横向移动**  
，侵入 CAN 总线或其他关键控制模块。  
  
## 风险说明  
  
虽然多数主机厂宣称 IVI 与动力系统物理隔离，但 PCA 研究指出：该隔离效果高度依赖厂商在网络分区与网关设计中的实现细节。在部分架构中，攻击者可能借由 IVI 打开进入更深层系统的“跳板”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgvicgOibfJv5FVZticJmXUibrcJuic9UDNvF8obBDUzF2vz4dlppvYWINalWEhaHgTyoaX2wuPAG6ibhTQ/640?wx_fmt=png&from=appmsg "")  
  
更进一步的攻击方式包括：  
- **通过 DNS 建立隐蔽 C2 信道**  
；  
  
- **通过弱加密引导启动过程绕过（Secure Boot Bypass）**  
；  
  
- **侵入独立通信模块并与 CAN 总线通信**  
，控制门锁、雨刷、方向盘等车辆关键部件。  
  
## 实战案例与关联研究  
- PCA 在 Black Hat Asia 2025 中展示了类似攻击如何完全远程控制一辆日产 Leaf。  
  
- Pen Test Partners 展示如何拦截 Renault Clio 的 CAN 总线控制信号，将整车转为“游戏手柄”。  
  
## 厂商回应（以大众为例）  
- 漏洞**仅限蓝牙通信层面**  
；  
  
- IVI 与驾驶控制系统隔离，**无法控制刹车、转向或发动机**  
；  
  
- 攻击需同时满足以下条件：  
  
- 攻击者需处于**5~7 米距离内**  
；  
  
- **车辆点火状态开启**  
；  
  
- **IVI 正在蓝牙配对中**  
；  
  
- 用户**需手动确认配对连接**  
。  
  
大众已推送 OTA 安全更新，部分车型需车主到维修点进行修复。  
## 防护建议  
- 用户应避免在公共区域将车辆置于蓝牙配对状态；  
  
- 检查蓝牙配对时的设备码是否匹配；  
  
- 尽快安装官方推送的软件更新；  
  
- 对 IVI 系统与 CAN 网关通信设计进行**安全审计与隔离验证**  
；  
  
- 针对车载系统的蓝牙通信栈加强 fuzzing 和静态分析。  
  
## 总结  
  
PerfektBlue 漏洞表明，即使是“非关键系统”如 IVI，在架构设计缺陷与通信协议漏洞的共同作用下，也可能演变为入侵整个车辆系统的突破口。**对蓝牙协议栈的供应链审计、通信隔离的架构级评估、以及 CAN 层防伪机制的强化，将是未来车载网络安全的重点。**  
  
如需漏洞PoC、设备检测脚本或隔离架构建议，请联系本单位安全团队获取技术支持。  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】DeepSeek再遭捷克封杀！](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=1&sn=0b6e4805766d104ac954112f8872fc2c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Coinbase事件撕开加密安全最脆弱的防线](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=2&sn=f58a0b0f5da56125d6d0c40e1e904f86&scene=21#wechat_redirect)  
  
  
  
[【安全圈】拿“123456”当密码，麦当劳6400万条求职信息存在泄露风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070622&idx=3&sn=5b53dd9b5f6d29081c504ae7e02b9dd2&scene=21#wechat_redirect)  
  
  
  
[【安全圈】ChatGPT 被绕过守护机制，泄露 Windows 产品密钥事件概述](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070608&idx=1&sn=4e5dc281a4812d0a3f756ec67d0bc633&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
