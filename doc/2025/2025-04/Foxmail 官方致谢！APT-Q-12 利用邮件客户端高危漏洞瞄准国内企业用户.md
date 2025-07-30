#  Foxmail 官方致谢！APT-Q-12 利用邮件客户端高危漏洞瞄准国内企业用户   
红雨滴团队  奇安信集团   2025-04-11 08:42  
  
概述  
  
奇安信威胁情报中心红雨滴团队于2025年初在威胁情报狩猎过程中观测到客户网络中的异常行为，  
协助应急响应时溯源到最初的邮件攻击来源，提取到了相关邮件，分析显示攻击者组合利用了 Foxmail 客户端存在的高危漏洞  
(QVD-2025-13936)，受害者仅需点击邮件本身即可触发远程命令执行，最终执行落地的木马。情报中心第一时间复现确认了所发现的新漏洞，并将其上报给腾讯 Foxmail 业务团队。目前该漏洞已经被修复，最新版的   
Foxmail 7.2.25 (2025-03-28) 不受影响，[Foxmail 团队给以了致谢](https://mp.weixin.qq.com/s?__biz=MjM5NzE1NjA0MQ==&mid=2651206985&idx=1&sn=9dfb24d14a78698366dc57cc7a2e1ec5&scene=21#wechat_redirect)  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehicicvIQibLicTWz7qFhI9K5CkI8YIpdia2RoWOwzEZqmX5kwzMuJ27d9G7KicL2HRCGCliaKffqhXdC0OjmQ/640?wx_fmt=png&from=appmsg "")  
  
  
奇安信威胁情报中心强烈建议Foxmail用户更新软件到最新版本以免受漏洞的利用攻击，目前天擎V10高级威胁模块可以支持对该漏洞的拦截，建议天擎客户在办公区和服务器区同时部署天擎并开启云查功能来抵御未知威胁：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8Ekar0NsicibX5CNaSWtiaMUpDhH3ycicSG4WUh7lKkt6CgL4C35tPicGvjfVdqALp3mmvFDjlDwhqPJA/640?wx_fmt=png&from=appmsg "")  
  
  
技术细节  
  
本次攻击使用的技战术是我们此前披露的 Operation DevilTiger[1]   
行动的延续，对于这类 CEF 软件的客户端，Web 漏洞+内置浏览器漏洞的组合实现远程命令执行仍然是最具攻击性的突防操作：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8Ekar0NsicibX5CNaSWtiaMUpcJSIpVSODDD6WLR5GynkXldjc9ghia2bEU7nTbFVofNru2KxI9j1TKQ/640?wx_fmt=png&from=appmsg "")  
  
  
本次活动中 APT-Q-12 使用了一个由 Rust 语言编写的全新特马，拥有文件上传、cmd 执行、文件读取、ssh 隧道等功能：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8Ekar0NsicibX5CNaSWtiaMUpOQIzhDC7zVEFJxf0tI3uMRSjYENTEGA6qJiarSiahnZictM7qFiabcJPdQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
检测  
  
目前，基于奇安信威胁情报中心的威胁情报数据的全线产品，包括奇安信威胁情报平台（TIP）、天擎、天眼高级威胁检测系统、奇安信NGSOC、奇安信态势感知等，都已经支持对此类攻击的精确检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2AqAgxkehic8Ekar0NsicibX5CNaSWtiaMUpmDgMK8tZFicbBSNVObrLy96CmrPEe9a35odagc3JRUqkJoEME2dLdXQ/640?wx_fmt=png&from=appmsg "")  
  
  
IOC  
  
暂不公开输出。  
  
  
参考链接  
  
[1].https://ti.qianxin.com/blog/articles/operation-deviltiger-0day-vulnerability-techniques-and-tactics-used-by-apt-q-12-disclosed-cn/  
  
