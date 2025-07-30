#  漏洞预警 | 网康NS-ASG应用安全网关源代码泄露漏洞   
浅安  浅安安全   2023-12-30 08:00  
  
**0x00 漏洞编号**  
- # 暂无  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
网康应用安全网关(NS-ASG)是一款软硬件一体化、性能卓越、集SSL与IPSec于一体的应用安全接入产品。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SWb8d466BsKYMQRW3jrCjGvw9SV8ibYqQvXx78bwVsCruKFDhf1gfnEZibQwMyZCgjrXQNNFZTJCVBw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
###   
###   
  
**漏洞类型：**  
源代码泄露  
  
**影响：**  
  
获取敏感信息  
  
****  
  
**简述：**  
网康NS-ASG应用安全网关6.3中存在源代码泄露漏洞，未授权攻击者可以通过/protocol/nsasg6.0.tgz获取源代码，进行代码审计。  
###   
  
**0x04 影响版本**  
- 网康NS-ASG应用安全网关6.3  
  
**0x05****POC**  
  
https://www.yuque.com/wangjie-0l1rh/prbq8b/iyxa0t8rntyve4s0  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方暂未发布漏洞修复版本，建议用户关注官网动态****：**  
  
https://www.netentsec.com/  
  
  
  
