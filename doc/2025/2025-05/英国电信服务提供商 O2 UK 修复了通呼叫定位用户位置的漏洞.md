#  英国电信服务提供商 O2 UK 修复了通呼叫定位用户位置的漏洞   
Rhinoer  犀牛安全   2025-05-25 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rlZd2qXyml4yHb51PPdlia7g7eFpl0Twpx7Uojic2pd0kLlgo8nnibkOqg/640?wx_fmt=png&from=appmsg "")  
  
O2 UK 的 VoLTE 和 WiFi 通话技术实施中存在一个漏洞，可能允许任何人通过呼叫目标来泄露某人的大致位置和其他标识符。  
  
该问题是由安全研究员丹尼尔·威廉姆斯 (Daniel Williams) 发现的，他表示该漏洞自 2017 年 3 月 27 日起就存在于 O2 UK 网络上，并于昨天得到解决。  
  
O2 UK 是维珍媒体 O2 旗下的一家英国电信服务提供商。截至 2025 年 3 月，该公司报告称其在英国拥有近 2300 万移动客户和 580 万宽带客户，是英国主要服务提供商之一。  
  
2017 年 3 月，该公司推出了 IP 多媒体子系统 (IMS) 服务，品牌为“4G 呼叫”，以提高通话期间的音频质量和线路可靠性。  
  
然而，正如威廉姆斯在分析此类通话期间的流量时发现的那样，通信双方交换的信令消息（SIP 标头）过于冗长且具有泄露性，其中包括 IMSI、IMEI 和小区位置数据。  
  
威廉姆斯解释道：“我从该网络获得的回复非常详细且冗长，与我之前在其他网络上看到的任何回复都不一样。”  
  
“这些消息包含的信息包括 O2（Mavenir UAG）使用的 IMS/SIP 服务器及其版本号、处理呼叫信息时出现问题时 C++ 服务偶尔会引发的错误消息以及其他调试信息。”  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rdxiaf6QryLoxqlSeGS3YFmbqlsmX2viaEsedSFB75iblNRGtQF98Xg7WA/640?wx_fmt=png&from=appmsg "")  
  
通过呼叫定位用户  
  
威廉姆斯使用已 root 权限的 Google Pixel 8 上的 Network Signal Guru (NSG) 应用程序，拦截了通话期间交换的原始 IMS 信令消息，并解码了小区 ID 以找到通话接收者连接的最后一个小区信号塔。  
  
然后，他使用提供手机信号塔地图的公共工具来查找信号塔的地理坐标。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rOCIzXQHUtdJDW1j2nVZDJxqRkScj87DPIyEq9JPIibCvr5wfzLtCj9w/640?wx_fmt=png&from=appmsg "")  
  
对于信号塔覆盖密集的城市地区，定位精度可达100平方米（1076平方英尺）。在农村地区，地理定位的精度会降低，但仍然可以确定目标位置。  
  
威廉姆斯发现，当目标在国外时，这个伎俩同样有效，因为他在丹麦哥本哈根找到了一个测试对象。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qvpgicaewUBlkqb2UwXDnXb0MYfKajE4rnNV9mSbHjSemWrxmQrawL1WXOAbs7dsQM9EDdBTWBJG5qJR9Zksrkw/640?wx_fmt=png&from=appmsg "")  
  
O2 UK 确认已修复  
  
威廉姆斯说，他在 2025 年 3 月 26 日和 27 日多次联系 O2 UK 报告他的发现，但没有得到答复。  
  
最后，他今天早些时候从 O2 UK 直接得到确认，该问题已得到解决，并且他通过测试证实了这一点。  
  
维珍媒体发言人在给 BleepingComputer 的声明中证实已经实施了修复，并指出客户无需采取任何措施来保护自己。  
  
Virgin Media O2 告诉 BleepingComputer：“我们的工程团队已经花了数周时间研究和测试修复方案 —— 我们可以确认该修复方案现已完全实施，并且测试表明该修复方案有效，我们的客户无需采取任何措施。”  
  
  
信息来源：B  
leepingComputer  
  
