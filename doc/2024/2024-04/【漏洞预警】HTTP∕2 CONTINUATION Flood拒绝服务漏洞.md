#  【漏洞预警】HTTP/2 CONTINUATION Flood拒绝服务漏洞   
cexlife  飓风网络安全   2024-04-07 21:13  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01upKWKyCWNkGj8zicRuEjdfQDJfhx8zXQZnZrQTzGJIKyiavBpFndKfE6xxiaTATDJQDozuRQV4h7Hg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**HTTP/2是一种安全高效的下一代http传输协议,旨在通过引入用于高效数据传输的二进制帧、允许通过单个连接进行多个请求和响应的多路复用以及用于减少开销的标头压缩来提高Web性能,HTTP/2 CONTINUATION帧用于连续字段块片段的序列,近日监测到HTTP/2协议被披露存在拒绝服务漏洞,该漏洞被称为“HTTP/2 CONTINUATION Flood”,可导致拒绝服务（DoS）攻击,在某些实现中可通过单个TCP连接使web服务器崩溃,目前该漏洞的技术细节已公开披露,由于某些HTTP/2协议实现中没有适当限制或清理单个数据流中发送的CONTINUATION 帧的数量,攻击者可通过不设置END_HEADERS标志位,向目标服务器发送CONTINUATION帧流,从而可能导致内存不足崩溃或CPU资源耗尽而导致服务器中断,造成拒绝服务。**影响范围:**已知HTTP/2 CONTINUATION Flood影响多个项目,不同的HTTP/2实现可能会有特定于该实现的独特漏洞及影响,不同HTTP/2实现相对应的部分CVE ID如下：Envoy（CVE-2024-27919、CVE-2024-30255）Tempesta FW ( CVE-2024-2758 )amphp/http ( CVE-2024-2653 )Golang（CVE-2023-45288）nghttp2（CVE-2024-28182）Apache HTTP Server ( CVE-2024-27316 )Apache Traffic Server ( CVE-2024-31309 )Node.js（CVE-2024-27983）值得注意的是,在某些受影响实现中,仅通过单个TCP连接就可能导致web服务器崩溃,且恶意请求可能在HTTP访问日志中不可见,这可能使得检测和分析更加困难。  
  
**安全措施:**升级版本目前部分供应商/项目已修复了相应漏洞,受影响用户可参考相关公告并及时更新:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01upKWKyCWNkGj8zicRuEjdfOuxXibC393P2IWy36Oibb06CrfbTFzrlXElR9F89nqBjiaddhb78u0WUg/640?wx_fmt=png&from=appmsg "")  
  
**临时措施:**暂无  
  
