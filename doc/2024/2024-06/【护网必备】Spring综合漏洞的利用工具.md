#  【护网必备】Spring综合漏洞的利用工具   
charonlight  七芒星实验室   2024-05-31 18:10  
  
**背景介绍**  
  
复现了几个spring之前的漏洞，顺手就武器化了下，工具目前支持Spring Cloud Gateway RCE(CVE-2022-22947)、Spring Cloud Function SpEL RCE (CVE-2022-22963)、Spring Framework RCE (CVE-2022-22965) 的检测以及利用，目前仅为第一个版本，后续会添加更多漏洞POC，以及更多的持久化利用方式  
  
**漏洞检测**  
  
工具支持单个漏洞单个目标检测，也支持多个目标检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnyvNlybZr8K637OSR9QrtnWgxiaNuJkPKpHlqqb2WWicUibBqCJu8FYYefFMREzlHHuf4eVYUXWOH0w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnyvNlybZr8K637OSR9QrtnwnN51R2GREA4rU1ycFlHfGLmnia5mfsTrbukNjcBp2fw2t6Qriast0iaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnyvNlybZr8K637OSR9QrtnCbKicjWW4YSibKzfzTodBlJWMXkwNANSa40DdT8jCufPsPHWm64SPLAg/640?wx_fmt=png&from=appmsg "")  
  
漏洞利用  
  
Spring Cloud Gateway RCE(CVE-2022-22947) 目前支持命令执行、一键反弹shell、哥斯拉内存马注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnyvNlybZr8K637OSR9Qrtnq3YYMOtxptpqyIL3M7tDSlbrYJDN1H9LrWicuvEt3dWt172uQde6lfQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnyvNlybZr8K637OSR9QrtnqsR4caxPtcrToMPlLiawicJiaiaKZGuctNiacfopZ0yzuyqJm2lqjibZuWibw/640?wx_fmt=png&from=appmsg "")  
  
Spring Cloud Function SpEL RCE (CVE-2022-22963)目前支持一键反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnyvNlybZr8K637OSR9QrtnAohe1IIPic6bjg0ERMZ68TufMicqUXf2QGaGKEwNK6Os3f0sp2QaTj0w/640?wx_fmt=png&from=appmsg "")  
  
Spring Framework RCE (CVE-2022-22965) 目前支持命令执行，通过写入webshell实现的，后续会继续实现写入ssh公钥、计划任务等利用方式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicnyvNlybZr8K637OSR9QrtnH3BlxXMLmb5d6nViczGFuicU4M1RbCxHtibeuPhLOopDmfHj2wJRfC3xg/640?wx_fmt=png&from=appmsg "")  
  
**免责声明**  
  
本  
开源工具是由作者按照开源许可证发布的，仅供个人学习和研究使用。作者不对您使用该工具所产生的任何后果负任何法律责任  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**240531****】获取**  
**下载链接**  
  
