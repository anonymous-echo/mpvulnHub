#  利用主流路由器漏洞传播，Mirai DDoS 恶意软件持续活跃   
 网络安全应急技术国家工程中心   2023-10-12 14:59  
  
Bleeping Computer 网站消息，基于 Mirai 的 DDoS 恶意软件僵尸网络 IZ1H9 近期又开始活跃了，为 D-Link、Zyxel、TP-Link、TOTOLINK 等 Linux 路由器“添加”了 13 个新有效载荷。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJFYvSqb54N5LbfVEYPWC7PlxnicibYwv3GmZIACTuibBgibUAvPjbpWWD8PSRwG6b0VaAiarhkiceIUAg/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
Fortinet 安全研究人员表示 9 月份的第一周， IZ1H9  恶意软件的利用率达到了历史峰值，针对易受攻击设备的利用尝试达到了数万次。IZ1H9 在成功入侵受害者设备后，便将其加入 DDoS 群，然后对指定目标发起 DDoS 攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJFYvSqb54N5LbfVEYPWC74Hu7jrOL51YuNdMLTKSiaMZHLQy9rdSe7jrQFLFw0NRKY24S92UaymQ/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
整个 9 月份观察到的利用尝试（Fortinet）  
  
**IZ1H9 瞄准众多攻击目标**  
  
众所周知，DDoS 恶意软件盯上的设备和漏洞越多，就越有可能建立一个庞大而强大的僵尸网络，以此对目标网站进行大规模攻击。就 IZ1H9 而言，Fortinet 报告称它使用了以下多个漏洞，时间跨度从 2015 年到 2023 年：  
> D-Link 设备：CVE-2015-1187、CVE-2016-20017、CVE-2020-25506、CVE-2021-45382  
> Netis WF2419：CVE-2019-19356  
> Sunhillo SureLine（8.7.0.1.1 之前的版本）：CVE-2021-36380  
> Geutebruck 产品：CVE-2021-33544、CVE-2021-33548、CVE-2021-33549、CVE-2021-33550、CVE-2021-33551、CVE-2021-33552、CVE-2021-33553、CVE-2021-33554  
> Yealink Device Management (DM) 3.6.0.20: CVE-2021-27561, CVE-2021-27562  
> Zyxel EMG3525/VMG1312（V5.50 之前）：CVE 未指定，但针对 Zyxel 裝置的 /bin/zhttpd/ 元件漏洞  
> TP-Link Archer AX21 (AX1800)：CVE-2023-1389  
> Korenix JetWave 无线 AP：CVE-2023-23295  
> TOTOLINK 路由器 CVE-2022-40475, CVE-2022-25080, CVE-2022-25079, CVE-2022-25081, CVE-2022-25082, CVE-2022-25078, CVE-2022-25084, CVE-2022-25077, CVE-2022-25076, CVE-2022-38511, CVE-2022-25075, CVE-2022-25083  
  
  
不仅如此， IZ1H9 网络攻击活动还针对与"/cgi-bin/login.cgi "路由相关的未指定 CVE，这可能会影响 Prolink PRC2402M 路由器  
  
**攻击链详情分析**  
  
在利用上述漏洞后，IZ1H9 有效载荷就会被立刻注入到受害者目标设备，其中包含一条从指定 URL 获取名为 "l.sh "的 shell 脚本下载器的命令。脚本执行后，会删除日志以隐藏恶意活动，接下来，它会获取针对不同系统架构定制的机器人客户端。  
  
最后，脚本会修改设备的 iptables 规则，以阻碍特定端口的连接，增加设备管理员从设备上删除恶意软件的难度。  
  
完成上述所有操作后，IZ1H9 僵尸网络就会与 C2（命令与控制）服务器建立通信，并等待执行命令。据悉，支持的命令涉及要发起的 DDoS 攻击类型，主要包括 UDP、UDP Plain、HTTP Flood 和 TCP SYN等。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJFYvSqb54N5LbfVEYPWC7AFYuHd6eYic7AhLp8SBiaWGMVr7Jc7nL77BkXAU70uEwwkOLawp6gsMA/640?wx_fmt=jpeg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
DDoS 命令（Fortinet）  
  
Fortinet 还在报告中指出，IZ1H9 的数据部分包含用于暴力破解攻击的硬编码凭证。以上这些攻击可能有助于传播到受害目标的相邻设备中，或对没有有效利用的 IoT 进行身份验证。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176nHLTvu485eg8ApncqgZgTmVLh3vV1uH5XKhibZT7zGE6ktial1LEUpUia1FGFRaPz8Iuq3ibbf5Aec4Q/640?wx_fmt=jpeg "")  
  
硬编码凭证（Fortinet）  
  
最后，网络安全专家建议物联网设备所有者使用强大的管理员用户凭据，并将其更新为最新可用的固件版本，在可能的情况下，尽量减少设备在公共互联网上暴露的频次。  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
