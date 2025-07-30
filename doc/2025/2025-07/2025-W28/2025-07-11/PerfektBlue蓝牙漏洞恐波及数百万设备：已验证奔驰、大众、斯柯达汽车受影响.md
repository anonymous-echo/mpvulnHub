> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMjQ5ODk5OA==&mid=2247511822&idx=3&sn=a8baaa8e70b7ce392afd82068e61c438

#  PerfektBlue蓝牙漏洞恐波及数百万设备：已验证奔驰、大众、斯柯达汽车受影响  
原创 网空闲话  网空闲话plus   2025-07-10 23:57  
  
2025年7月10日，安全研究机构PCA Cyber Security公开了影响OpenSynergy BlueSDK蓝牙协议栈的“PerfektBlue”漏洞系列。该漏洞链条由四个关键缺陷组成，涵盖高危的Use‑After‑Free（UAF）问题与中低危的逻辑错误，能够让攻击者在一键配对后远程执行任意代码（RCE）。凭借“最多一次点击”的利用门槛，此攻击可在数百万台目标设备上横向应用，最先在主流车载信息娱乐系统（IVI）中得到验证，随后波及包含消费电子在内的其他行业。本文从漏洞成因、影响分析、实验演示与缓解建议五个方面，对PerfektBlue进行深入解读与预警。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVocbXwL8UcaxKzHMo5CVGpjTIKlxUb9uDMnSA8vAlxd1WZjZWGIXNoDy8zmvlaYDRA8Hp1EfnhGw/640?wx_fmt=png&from=appmsg "")  
  
漏洞背景与发现  
  
OpenSynergy的BlueSDK是一款闭源的蓝牙协议栈实现，支持经典BR/EDR与LE低功耗两大模式，并包含包括A2DP、AVRCP、L2CAP、RFCOMM在内的三十余种蓝牙配置文件。由于其高可定制性、开放许可以及硬件无关性，BlueSDK被广泛集成在汽车IVI系统、工控终端与某些移动设备中。  
  
PCA安全评估团队在2024年5月对BlueSDK二进制文件进行逆向分析，首次识别出四个内存与逻辑缺陷。团队于5月17日与OpenSynergy安全团队取得联系，交换公钥并提交首轮咨询报告；6月19日完成在大众ID.4信息娱乐系统（ICAS3）上的首次PoC验证；7月15日得到OpenSynergy确认，并于9月发布修复补丁。然而，PCA在2025年6月发现，除少数厂商外，多数整车厂并未将补丁推送至终端用户，导致漏洞在真实环境中长期暴露。  
  
漏洞概述  
  
1. CVE‑2024‑45434：AVRCP服务UAF（CVSS 3.1 8.0，高危）  
  
该缺陷位于BlueSDK对AVRCP（音视频远程控制配置文件）的实现中。当栈上对象被释放后，残留引用并未进行清理，攻击者可发送特制的控制命令触发二次释放，借助UAF漏洞获得代码执行。PoC演示表明，在NTG6主机上攻击者可获取反向Shell，权限为phone用户。  
  
2. CVE‑2024‑45431：L2CAP CID验证缺失（CVSS 3.1 3.5，低危）  
  
L2CAP协议用于多路复用Bluetooth逻辑链路，该漏洞源自未对远程CID（通道标识符）做严格验证。攻击者能伪造或置空CID，扰乱协议状态机，并为后续攻击链提供便利条件。此问题虽单独严重性较低，但在配合其他缺陷时增加链式利用稳定性。  
  
3. CVE‑2024‑45433：RFCOMM异常终止（CVSS 3.1 5.7，中危）  
  
RFCOMM模拟串行端口通信，允许基于串口协议的应用运行。该缺陷在检测到错误条件后，函数返回控制流出错，未执行完整清理逻辑，攻击者可借此绕过安全验证，执行恶意函数。  
  
4. CVE‑2024‑45432：RFCOMM参数错误（CVSS 3.1 5.7，中危）  
  
该漏洞体现于RFCOMM某些函数调用中使用了未初始化或错误的变量作为参数，导致逻辑分支被不当触发，可引发信息泄露或堆栈混淆，为进一步RCE创造条件。  
  
串联利用与一键式RCE  
  
单独利用上述缺陷已有风险，但PCA团队发现可将UAF与RFCOMM逻辑缺陷串联，通过一次合法配对后发送连续精心构造的蓝牙数据包，实现稳定的远程Shell。整个链条只需用户在配对提示框点击“确认”一次，或在部分车型中甚至无需交互（“Just Works”配对模式），即可被攻击者利用。  
  
影响分析  
  
4.1 汽车行业  
  
梅赛德斯‑奔驰 NTG6/NTG7：PCA在配备NTG6（固件2020-2021）和最新世代NTG7的测试平台上均成功触发PerfektBlue攻击。攻击者可通过AVRCP的UAF缺陷获得反向Shell，并操控车载媒体进程，进一步读取GPS坐标、录制车内音频、访问电话簿等。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVocbXwL8UcaxKzHMo5CVGpZO0G2oJCfFTlY1kqKvmKYLWO5ezG1ohAib4CkLwGiaEb2TWsunJnGUPg/640?wx_fmt=webp&from=appmsg "")  
  
成功利用蓝牙漏洞后在TCP/IP协议上获得的反向shell的演示。可以看到，蓝牙进程是以phone用户权限启动的。  
  
大众 ID.4（MEB ICAS3）：测试涵盖两种固件（ID软件版本2.1与3.2.12），分别对应固件0792与0561。PoC演示中，攻击者获得sint_sec_btapp进程权限，并可在TCP/IP层向车载网关或其他ECU横向移动。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVocbXwL8UcaxKzHMo5CVGpNRp9Yb71xpDCP3yaTmeSnvJN867Ho9u9uCvYFibhia0KeRf1NCoCKWGA/640?wx_fmt=webp&from=appmsg "")  
  
成功利用蓝牙漏洞（针对0561不同固件版本）后，在TCP/IP协议上获得的反向Shell。如图所见，蓝牙进程已以sint_sec_btapp用户权限启动。  
  
斯柯达 Superb（MIB3 系统）：测试使用MIB3 0304固件，攻击者同样在蓝牙进程上下文执行反向Shell。据PCA称，所有采用BlueSDK的MIB3主机均存在类似风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icVocbXwL8UcaxKzHMo5CVGpz3ogAJlr1RXBpMDTD5Vwa5UHhJickEo0Rjlxq4yFsrdMCBOlGPuzwsg/640?wx_fmt=webp&from=appmsg "")  
  
成功利用蓝牙漏洞后在TCP/IP协议上获得的反向shell的演示。可以看到，蓝牙进程是以phone用户权限启动的。  
  
整车厂反馈与部署状况参差：大众汽车已开启调查并确认在“特定条件”下可被利用；梅赛德斯尚未正式回复；斯柯达迄今未对外表态。  
  
4.2 其他行业  
  
BlueSDK并不限于汽车领域。一些工控终端、便携设备、POS机及专业音响中亦集成该协议栈。由于PCA团队无法访问源码，仍有可能在其他行业设备中发现PerfektBlue链条。安全公告中提醒所有使用BlueSDK的OEM与终端厂商立即审计相关产品。  
  
实验演示  
  
在PCA举办的两场封闭演示中，研究人员展示了PerfektBlue从配对到RCE的全过程：  
  
配对阶段：研究员将攻击设备设为“可见”，IVI显示蓝牙配对请求，用户点击“确认”或无需交互；  
  
数据包注入：利用L2CAP伪造CID及RFCOMM异常触发机制，将UAF链解锁并插入shellcode；  
  
Shell输出：在TCP/IP隧道上，攻击者通过标准端口与受害主机建立连接，进入命令行环境；  
  
后续横移：研究员从IVI内网扫描其他ECU，如导航模块、OBD端口控制器，验证了在同一车内的横向移动可能性。  
  
该实验证明，无需物理接触车辆，仅依靠蓝牙短距无线信号与配对交互，即可完成破坏性极高的远程入侵。  
  
风险与威胁  
  
隐私泄露：攻击者可实时获取GPS坐标与乘客对话录音；  
  
金融与身份盗用：访问车主通讯录或已存支付凭证；  
  
行车安全操控：通过横向移动至安全关键ECU，可能控制制动与转向；  
  
供应链级连效应：补丁未及时部署的车辆大规模分布在千万辆级，存在群体攻击风险；  
  
跨行业扩散：BlueSDK在其他领域应用，可能蔓延至关键基础设施和医疗设备。  
  
随着车联网与IoT设备的普及，PerfektBlue类型的“无线一击”式攻击链将成为未来攻击者的新常态。  
  
漏洞披露时间线  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icVocbXwL8UcaxKzHMo5CVGpicmrAmmS81Cr89IItWic5wAdB7AJwLUZBR8uWvJWoVkIPuRAJAq4iawkQ/640?wx_fmt=png&from=appmsg "")  
  
缓解建议  
  
立即升级与补丁部署；所有使用BlueSDK的OEM厂商应优先部署包含CVE‑2024‑45431至45434修复的固件版本，并向终端用户推送OTA或经销商更新。  
  
强化配对安全；禁用“Just Works”模式，仅使用Passkey Entry或Numeric Comparison，确保蓝牙配对需用户输入PIN或确认数字。  
  
最小化服务暴露；遵循最小权限原则，关闭未使用的配置文件（如AVRCP、RFCOMM），仅启用必要的HFP或MAP等。  
  
网络与进程隔离；将IVI系统与车辆CAN总线等安全关键网络物理或逻辑隔离，防止RCE后横向渗透至控制系统。  
  
检测与监控；在车载网关和安全运营中心（SOC）部署基于蓝牙行为的入侵检测，监控异常L2CAP/CID分配与RFCOMM异常，应立即报警并阻断连接。  
  
供应链透明度；建立蓝牙组件的版本管理与追踪机制，确保嵌入式软件更新的可见性，减少补丁延迟。  
  
行业协作与演练；汽车安全研究机构、标准组织、监管机构需联合开展漏洞演练与公告，实现快速信息共享。  
  
结论  
  
PerfektBlue揭示了闭源蓝牙堆栈在嵌入式及车用场景中的安全盲点。汽车厂商与其他行业设备提供商需深刻认识到无线接口的威胁模型，在设计阶段引入安全评估、在运维阶段强化补丁管理与行为监控。面对“最多一次点击”的零日攻击链，构建多层防御、加强供应链透明与跨行业协同，才是遏制类似PerfektBlue事件重演的根本之道。唯有从架构、流程与协作全方位提升蓝牙通信的安全性，才能在智能互联的新时代守护用户与公共安全。  
  
参考资源  
  
1、  
https://www.bleepingcomputer.com/news/security/perfektblue-bluetooth-flaws-impact-mercedes-volkswagen-skoda-cars/  
  
2、  
https://pcacybersecurity.com/resources/advisory/perfekt-blue  
  
3、  
https://perfektblue.pcacybersecurity.com/  
  
