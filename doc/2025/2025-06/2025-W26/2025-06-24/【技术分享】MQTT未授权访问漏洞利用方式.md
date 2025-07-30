> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMTY1MTIzOA==&mid=2247484700&idx=1&sn=3975752bd19d84f8561d610262fd94e2

#  【技术分享】MQTT未授权访问漏洞利用方式  
剁椒Muyou鱼头  剁椒Muyou鱼头   2025-06-24 00:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
**阅读须知**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
  
****  
**本公众号文章皆为网上公开的漏洞，仅供日常学习使用，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把**剁椒Muyou鱼头**  
“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD01hM2Bw8oTpcNCZl68Bj8T0aLpOHAMFCv9Qd6KeeQgTscOURdQUDbLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4Z7hc6oGV6C6IwibzfQUM1oq1yUciadAKQ3Ap29o8GGnBU52wXgSSicBxQ/640?wx_fmt=gif "")  
  
  
****  
**2025/06/24 星期二**  
  
**多云·北风2级**  
  
  
//01 前言  
  
  
    最近刷微信公众号刷到一师傅写的  
MQTT未授权漏洞相关的文章，以前都没注意过这个漏洞，也不知道怎么利用。正好最近在做某项目相关互联网业务渗透测试时，遇到了大量的MQTT以及RTSP协议，随即想到了这个未授权漏洞可以凑凑数。凑个字数  
凑个字数。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1wRXu1vxJ3hKUXU1lrMvyfXA1kqYHXOSCjrEe2Ww01xkYQ2ejr7sdReMuJW181sEQn9N3oDGDYHQ/640?wx_fmt=png&from=appmsg "")  
  
  
//02   
MQTT  
  
  
      
MQTT（Message Queuing Telemetry Transport）是一种轻量级的发布/订阅协议，专为低带宽、高延迟或不可靠网络环境下的物联网设备通信设计。它通过最小化协议开销实现高效数据传输，支持一对多消息分发，适用于传感器数据采集、远程监控等场景。其核心优势包括低功耗、低代码量、实时性强，并支持QoS保障消息可靠性。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1wRXu1vxJ3hKUXU1lrMvyf8bxeloRDp0ib9PyWPCacEl4Vy1RfdGiaJVcYOzgic4sfovIVRcvmicW6cw/640?wx_fmt=png&from=appmsg "")  
  
  
//03 MQTT未授权检测  
  
  
      
我这边是使用的  
TscanPlus这款工具，  
一款综合性网络安全检测和运维工具，旨在快速资产发现、识别、检测，构建基础资产信息库，协助甲方安全团队或者安全运维人员有效侦察和检索资产，发现存在的薄弱点和攻击面。在他的密码破解模块中有MQTT爆破，还有其他大佬写的一些检测脚本可以去Github、微信公众号上搜一下。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1wRXu1vxJ3hKUXU1lrMvyfZibzu6yAYYP3jPx7mX1vFeSWia7tgib27XqFg30XeL6L1ibOFkCnyGic86A/640?wx_fmt=png&from=appmsg "")  
  
  
//04 MQTT未授权利用  
  
  
      
漏洞利用可以直接使用  
MQTTX的桌面客户端，  
MQTTX 是由 EMQ 开发的一款开源跨平台 MQTT 5.0 桌面客户端，它兼容 macOS，Linux 以及 Windows 系统。 MQTTX 的用户界面 UI 采用聊天式设计，使得操作逻辑更加简明直观。它支持用户快速创建和保存多个 MQTT 连接，便于测试 MQTT/MQTTS 连接，以及 MQTT 消息的订阅和发布。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA1wRXu1vxJ3hKUXU1lrMvyfuEP4mWKOHNdq5LnRmP0puvPqUgSxlqlZMiauy6cVR1DnMibzNmicG5HLQ/640?wx_fmt=png&from=appmsg "")  
  
  
//05 结尾  
  
  
    没有什么技术含量的操作，主打一个凑漏洞写报告使用，根据资产扫描默认端口或者大多数情况下会更改端口，可以使用探测工具探测一下就可以愉快的扫描碰运气了。  
  
  
  
    
END   
  
  
   
作者 | 剁椒Muyou鱼头  
   
  
I like you,but just like you.  
  
我喜欢你，仅仅如此，喜欢而已~  
  
  
  
  
**********点赞在看不迷路哦！**  
  
  
