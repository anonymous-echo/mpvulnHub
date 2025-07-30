#  三星Exynos芯片集中发现18个0 day漏洞，影响三星、vivo设备   
ang010ela  嘶吼专业版   2023-03-24 12:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
谷歌研究人员在三星Exynos芯片集中发现18个0 day漏洞。  
# 漏洞概述  
  
谷歌Project Zero安全研究人员在三星Exynos芯片集中发现18个0 day漏洞，影响手机、可穿戴设备和汽车等电子设备。  
  
这18个漏洞是在2022年底到2023年初发现和报告的。其中4个漏洞最为严重，可以实现互联网到基带的远程代码执行。其中一个漏洞已取得CVE编号（CVE-2023-24033），其他漏洞正在等待编号分配。攻击者利用漏洞可以在没有任何用户交互的情况下远程入侵有漏洞的设备。CVE-2023-24033漏洞产生的原因是基带软件未适当检查SDP中指定的accept类型属性的格式类型，可能会引发基带的DoS或代码执行。其余3个漏洞由于尚未修复，因此研究人员决定暂不公开漏洞细节。  
  
其他14个漏洞中有5个取得了CVE编号，分别是CVE-2023-24072、CVE-2023-24073、CVE-2023-24074、CVE-2023-24075和CVE-2023-24076。这些漏洞的利用需要有本地访问权限或由恶意网络运营商发起，因此利用的难度较高。  
# 漏洞影响  
  
受影响的设备包括：  
  
三星手机设备：S22、M33、M13、M12、 A71、A53、A33、A21、A13、A12 和A04 系列；  
  
Vivo手机设备：S16、S15、S6、X70、X60 和 X30系列；  
  
谷歌手机设备：Pixel 6和Pixel 7系列；  
  
使用Exynos W920芯片集的可穿戴设备；  
  
使用Exynos Auto T5123芯片集的车辆。  
# 漏洞补丁  
  
三星已经为相关厂商提供了修复漏洞的安全更新，但补丁信息未公开。具体设备的补丁修复时间与具体厂商有关，比如谷歌已在2023年3月的安全更新中发布了Pixel设备的安全补丁。  
  
谷歌和三星确认用户可以禁用WiFi电话和VoLTE的方式来避免受到攻击的影响。此外，谷歌研究人员建议用户在补丁发布后尽快安装。  
  
更多参见谷歌project zero：https://googleprojectzero.blogspot.com/2023/03/multiple-internet-to-baseband-remote-rce.html  
  
参考及来源：https://www.bleepingcomputer.com/news/security/google-finds-18-zero-day-vulnerabilities-in-samsung-exynos-chipsets/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29jk6sAIvOAqrFIiczkWEMeMqgWl9MbggPwGvhKvytdDGvNR3I5mE3l2m5I2eAWbwrJs6qTg8RgzQA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o29jk6sAIvOAqrFIiczkWEMeMReJCBk2G2qzIhEb5ZPNyeLOsHiaXw00dPTVYSFehVI5rp10XwibN3rMA/640?wx_fmt=png "")  
  
  
