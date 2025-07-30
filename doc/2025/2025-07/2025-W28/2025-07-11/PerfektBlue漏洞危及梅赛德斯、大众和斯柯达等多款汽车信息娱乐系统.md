> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458597083&idx=3&sn=5ed9d81521495a3efbc2a3afe6aedaf8

#  PerfektBlue漏洞危及梅赛德斯、大众和斯柯达等多款汽车信息娱乐系统  
看雪学苑  看雪学苑   2025-07-11 09:59  
  
近日，网络安全研究机构  
PCA Cyber Security  
发现了一组名为  
“PerfektBlue”  
的严重漏洞，这些漏洞存在于OpenSynergy公司的BlueSDK蓝牙框架中，  
可能导致全球数百万辆汽车的信息娱乐系统被远程攻击。  
  
  
BlueSDK作为广泛应用于汽车行业的蓝牙解决方案，支持经典蓝牙和低功耗模式，且具有硬件无关性，允许厂商根据需求定制。但这种灵活性也使其成为安全隐患的温床。研究显示，  
攻击者利用这些漏洞可实现远程代码执行，进而对车载系统进行操控，包括追踪车辆位置、录制车内音频、获取电话簿数据等，甚至可能横向渗透至转向、雨刮等关键功能（目前尚未实际演示）。  
  
  
实施PerfektBlue攻击的核心条件是与目标设备配对以达到相应安全通信级别，但由于BlueSDK的框架特性，不同设备的配对流程差异较大——配对请求次数可能有限制或无限制，可能需要用户交互，也可能完全禁用。不过，攻击者最多只需一次用户点击，就能通过无线方式利用漏洞。  
  
  
此次发现的漏洞包括四项，具体信息如下：  
  
- CVE-2024-45434：AVRCP服务中的“使用后释放”漏洞，CVSS 3.1评分8.0（严重）  
  
- CVE-2024-45431：L2CAP通道远程CID验证不当，评分3.5（低）  
  
- CVE-2024-45433：RFCOMM中函数终止错误，评分5.7（中）  
  
- CVE-2024-45432：RFCOMM中函数调用参数错误，评分5.7（中）  
  
  
研究人员已在奔驰NTG6、大众MEB ICAS3、斯柯达MIB3等信息娱乐主机上成功演示攻击，并开发了相关概念验证漏洞利用程序。他们指出，这些漏洞在部分设备上可能无需配对即可利用，具体取决于厂商的实现方式。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8HibWZib3TdstmyRIr0a4KdwYrXFpJibs0c4EfKc7h5qIs3Gd0LoWUfrxlkso0bPAsVPoibqryf1OSRdw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞披露过程一波三折。PCA于2024年5月17日向OpenSynergy报告问题，该公司7月确认并着手修复，9月完成补丁开发。2025年3月，PCA启动负责任披露流程，但某受影响车企6月称未收到补丁。最终，PCA于7月7日正式发布安全公告，旨在推动整个行业加快修复速度，提升安全水平。  
  
  
安全专家建议，用户应尽快更新车载系统软件，或暂时关闭蓝牙功能以降低风险。  
  
  
  
资讯来源：  
securityaffairs  
  
转载请注明出处和本文链接  
  
  
﹀  
  
﹀  
  
﹀  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibE1yC1VFg5b1Fw8RncvZh2CWWiazpL6gPXp0lXED2x1ODLVNicsagibuxRw/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fjcl6q2ORwibt8PXPU5bLibExiboJzOiafqGLvlOkrmU6NIr3qSr7ibpkIo2N5mhCTNXoMl37s2oRSIDw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
