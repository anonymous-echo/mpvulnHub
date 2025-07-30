> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NzAwOTg4NQ==&mid=2649795449&idx=2&sn=404c6ef81f1ab1d5139b13e0918bb13b

#  SinoTrack GPS 漏洞可能允许攻击者跟踪和控制车辆  
会杀毒的单反狗  军哥网络安全读报   2025-06-17 01:00  
  
**导****读**  
  
  
  
影响 SinoTrack GPS 跟踪平台的漏洞可能允许攻击者监视车辆的位置，甚至执行诸如断开车辆燃油泵电源之类的操作（如果跟踪器可以与汽车的系统交互）。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaFgB3z9EPBPq5nMIyJ7tZBWic0yJvr5zJHSdvAgpGIW4bW4ichrJ6sLZRt4O8TFMgUAIRB5IMHwGQ2A/640?wx_fmt=webp&from=appmsg "")  
  
  
该警告是美国网络安全和基础设施安全局 (CISA) 上周根据安全研究员 Raúl Ignacio Cruz Jiménez 的报告发出的，目前这些漏洞尚未得到修补。  
  
  
SinoTrack是一家专注于GPS追踪设备和车队管理解决方案的制造商。据该公司称，其GPS追踪器已在全球超过600万辆车辆上安装。  
  
  
研究人员标记的漏洞（CVE-2025-5484、CVE-2025-5485）影响所有版本的 SinoTrack IOT PC 平台，该平台将 GPS 追踪器连接到 Web/应用程序管理界面，该界面提供仪表板、警报，并且（根据追踪器型号）可实现对某些功能的远程控制。  
  
  
SinoTrack GPS 追踪器通过使用设备的唯一 ID（最多 10 位数字组成的数字标识符）和密码向平台进行身份验证。  
  
  
但是，虽然所有设备的用户名可能是唯一的，但它也会打印在跟踪器上，这意味着如果攻击者可以物理访问设备或可以从公开的设备图片（例如，从 Ebay 列表）中收集它，他们就可以发现它。  
  
  
CISA 解释说，攻击者还可以“通过增加或减少已知标识符或通过枚举随机数字序列来枚举潜在目标”。  
  
  
再加上用户在设置追踪器时不需要更改公开的默认密码，因此被利用的可能性就变得显而易见。  
  
  
CISA 表示，“SinoTrack 没有回应 CISA 的协调请求”，并敦促该公司追踪器的用户尽快将默认密码更改为独特、复杂的密码，并隐藏设备标识符。  
  
  
他们补充道：“如果贴纸出现在可公开访问的照片上，请考虑删除或替换照片以保护标识符。”  
  
  
CISA  
官方安全公告：  
  
https://www.cisa.gov/news-events/ics-advisories/icsa-25-160-01  
  
  
新闻链接：  
  
https://www.helpnetsecurity.com/2025/06/16/sinotrack-gps-vulnerabilities-may-allow-attackers-to-track-control-vehicles/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AnRWZJZfVaGC3gsJClsh4Fia0icylyBEnBywibdbkrLLzmpibfdnf5wNYzEUq2GpzfedMKUjlLJQ4uwxAFWLzHhPFQ/640?wx_fmt=jpeg "")  
  
扫码关注  
  
军哥网络安全读报  
  
**讲述普通人能听懂的安全故事**  
  
  
