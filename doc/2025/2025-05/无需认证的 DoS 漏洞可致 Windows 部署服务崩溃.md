#  无需认证的 DoS 漏洞可致 Windows 部署服务崩溃   
 信息安全大事件   2025-05-08 09:38  
  
漏洞详情  
  
网络安全研究员Zhiniang Peng发布的技术分析报告显示，Windows部署服务（WDS，Windows Deployment Services）中新曝光的拒绝服务（DoS，Denial of Service）漏洞可能对企业网络造成严重影响。该漏洞允许攻击者通过伪造的UDP数据包耗尽系统内存，导致服务器在数分钟内完全失去响应——整个过程无需任何认证或用户交互。  
  
Peng在报告中指出："我们证实了WDS中存在远程DoS漏洞，攻击者无需认证（预认证）或用户交互（零点击）即可使WDS网络崩溃。"  
  
技术原理  
  
该漏洞根源在于WDS使用基于UDP的TFTP服务（端口69）通过PXE启动传输Windows安装镜像。当客户端连接服务器时，WDS会分配一个CTftpSession对象，但系统对可创建的会话数量没有限制。  
  
报告指出："核心问题在于EndpointSessionMapEntry未对会话数量进行限制。攻击者可伪造客户端IP地址和端口号，不断创建新会话直至系统资源耗尽。"  
  
在配备8GB内存的Windows Server Insider Preview测试环境中，Peng仅通过发送大量源地址和端口随机的伪造UDP数据包，就可在7分钟内使整个系统崩溃。  
  
攻击方法  
  
攻击实施仅需三个步骤：  
- 伪造具有随机源IP和端口的UDP数据包  
  
- 将这些数据包发送至目标WDS服务器的69端口  
  
- 利用WDS在内存中无限制创建和存储会话对象的缺陷  
  
虽然出于道德考虑Peng仅提供了伪代码，但该漏洞利用技术实现简单，攻击者只需在运行Ubuntu等操作系统的设备上编写基础脚本即可实施攻击。  
  
微软回应  
  
该漏洞于2025年2月8日报告给微软，并于3月4日获得确认。但微软在4月23日表示该漏洞"未达到安全服务修复标准"，决定不予修复。  
  
Peng对此决定提出尖锐批评："我们认为这在其SDL标准中仍属重要DoS漏洞，与微软就此事的沟通令人非常失望。"他强调这是种零点击攻击，可远程瘫痪基于PXE的部署基础设施，对依赖WDS的组织构成严重威胁。  
  
防护建议  
  
鉴于微软未发布修复补丁，明确建议："为保护PXE网络免受此威胁，请勿使用Windows部署服务。"  
  
来源：FreeBuf  
  
  
**推荐阅读**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/JqliagemfTA6iaLkNkoIyrcTq1jErRmY0MJ1z1xtCujHY8tntYedwef2pfhZUHEXS4N3lrn50zibmkuRDVu9D85dg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
**1**  
  
[江苏国骏网络安全服务业务全景 ](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247490721&idx=2&sn=6a12cec92cbb74648773060c6255aa01&scene=21#wechat_redirect)  
  
  
**2**  
  
[常见网络安全问题及对应产品措施指南 ](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247492357&idx=2&sn=8357e6b1145623c90a697ae430e01f52&scene=21#wechat_redirect)  
  
  
**3**  
  
[常见网络安全解决方案场景适配与核心防护全攻略](https://mp.weixin.qq.com/s?__biz=MzkzNjIzMjM5Ng==&mid=2247492501&idx=1&sn=32ddf66fafda9f81f50bf6ce8c48d018&scene=21#wechat_redirect)  
  
  
**4**  
  
# 【业务介绍】勒索病毒专项防护工作业务  
  
  
  
  
  
  
