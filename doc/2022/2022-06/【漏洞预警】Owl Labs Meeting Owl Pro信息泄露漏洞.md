#  【漏洞预警】Owl Labs Meeting Owl Pro信息泄露漏洞   
安识科技  SecPulse安全脉搏   2022-06-10 16:56  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/JVDECnNjedGVpoJMz3uW6z4rwwr0GJK5GwTjjMX8HdkwxuFiavhibvca4qAlXTKCaE6YGkZibSKEebNtAC56WAeNtibxuAjPgSAJ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/qE9MKluetOlD8gpGKew1L3bpxQxia8sSu6bicyAqpRpICVLyPe0q1KBPcqxTdGsXVKuM4bZEYAqMXtWD9UKm7QmrDIADHSknIv/640?wx_fmt=svg "")  
  
1. **通告信息**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/anblvjPKYbMeTTBE04NJlC7xdHcTw0Zr2pw7oRyyyU1OcS1bxCDIicTTfULAxI3Nnsxp4DQrOfHEicHzybp6icibpcHM9168PpAZ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/SYeWkon6C6JqUEnNYf8gnGKoWbXBpu9W48RrnGlj4ia1vX8m9PvwR0icA3q8DTEbJZHje4bZ2KDUP5DJP7PRxvmxyXs3UEYMOR/640?wx_fmt=svg "")  
  
  
  
近日，  
安识科技  
A-Team团队  
监测到一则   
Meeting Owl Pro 和 Whiteboard Owl  
   
组件存在  
信息泄露漏洞  
的信息，该漏洞的  
CVSS评分为7.4  
，  
漏洞编号：  
CVE-2022-31460  
，漏洞威胁等级：高危。  
Owl Labs Meeting Owl 5.2.0.15 中可通过特定的c 150 值使用硬编码的 hoothoot 凭据激活Tethering模式。除CVE-2022-31460外，Meeting Owl Pro 和 Whiteboard Owl中还存在多个安全漏洞：  
  
l  
CVE-2022-31459：Owl Labs Meeting Owl 5.2.0.15中可使用蓝牙通过特定c 10值检索密码哈希，该漏洞的CVSS评分为7.4。  
  
l  
CVE-2022-31461：Owl Labs Meeting Owl 5.2.0.15 中可通过特定 c 11 消息停用密码保护机制，该漏洞的CVSS评分为7.4。  
  
l  
CVE-2022-31462：Owl Labs Meeting Owl 5.2.0.15中允许使用在蓝牙广播数据中发现的后门密码（源自序列号）来控制设备，该漏洞的CVSS评分为9.3。  
  
l  
CVE-2022-31463：Owl Labs Meeting Owl 5.2.0.15中不要求蓝牙密码，因为只使用客户端认证，该漏洞的CVSS评分为8.2。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防  
  
工作，以免遭受黑客攻击。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_svg/JVDECnNjedGVpoJMz3uW6z4rwwr0GJK5GwTjjMX8HdkwxuFiavhibvca4qAlXTKCaE6YGkZibSKEebNtAC56WAeNtibxuAjPgSAJ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/qE9MKluetOlD8gpGKew1L3bpxQxia8sSu6bicyAqpRpICVLyPe0q1KBPcqxTdGsXVKuM4bZEYAqMXtWD9UKm7QmrDIADHSknIv/640?wx_fmt=svg "")  
  
2. **漏洞概述**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/anblvjPKYbMeTTBE04NJlC7xdHcTw0Zr2pw7oRyyyU1OcS1bxCDIicTTfULAxI3Nnsxp4DQrOfHEicHzybp6icibpcHM9168PpAZ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/SYeWkon6C6JqUEnNYf8gnGKoWbXBpu9W48RrnGlj4ia1vX8m9PvwR0icA3q8DTEbJZHje4bZ2KDUP5DJP7PRxvmxyXs3UEYMOR/640?wx_fmt=svg "")  
  
  
  
CVE  
：  
CVE-2022-31460  
  
简述：  
Meeting Owl Pro 是Owl Labs公司的一款视频会议设备，它在政府、教育等行业中被广泛使用。Meeting Owl Pro 和 Whiteboard Owl中的一个信息泄露漏洞（CVE-2022-31460），该漏洞的CVSS评分为7.4。Owl Labs Meeting Owl 5.2.0.15 中可通过特定的c 150 值使用硬编码的 hoothoot 凭据激活Tethering模式。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/JVDECnNjedGVpoJMz3uW6z4rwwr0GJK5GwTjjMX8HdkwxuFiavhibvca4qAlXTKCaE6YGkZibSKEebNtAC56WAeNtibxuAjPgSAJ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/qE9MKluetOlD8gpGKew1L3bpxQxia8sSu6bicyAqpRpICVLyPe0q1KBPcqxTdGsXVKuM4bZEYAqMXtWD9UKm7QmrDIADHSknIv/640?wx_fmt=svg "")  
  
3. **漏洞危害**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/anblvjPKYbMeTTBE04NJlC7xdHcTw0Zr2pw7oRyyyU1OcS1bxCDIicTTfULAxI3Nnsxp4DQrOfHEicHzybp6icibpcHM9168PpAZ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/SYeWkon6C6JqUEnNYf8gnGKoWbXBpu9W48RrnGlj4ia1vX8m9PvwR0icA3q8DTEbJZHje4bZ2KDUP5DJP7PRxvmxyXs3UEYMOR/640?wx_fmt=svg "")  
  
  
  
攻击者可通过特定的  
c 150 值使用硬编码的 hoothoot 凭据激活Tethering模式  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/JVDECnNjedGVpoJMz3uW6z4rwwr0GJK5GwTjjMX8HdkwxuFiavhibvca4qAlXTKCaE6YGkZibSKEebNtAC56WAeNtibxuAjPgSAJ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/qE9MKluetOlD8gpGKew1L3bpxQxia8sSu6bicyAqpRpICVLyPe0q1KBPcqxTdGsXVKuM4bZEYAqMXtWD9UKm7QmrDIADHSknIv/640?wx_fmt=svg "")  
  
4. **影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/anblvjPKYbMeTTBE04NJlC7xdHcTw0Zr2pw7oRyyyU1OcS1bxCDIicTTfULAxI3Nnsxp4DQrOfHEicHzybp6icibpcHM9168PpAZ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/SYeWkon6C6JqUEnNYf8gnGKoWbXBpu9W48RrnGlj4ia1vX8m9PvwR0icA3q8DTEbJZHje4bZ2KDUP5DJP7PRxvmxyXs3UEYMOR/640?wx_fmt=svg "")  
  
  
  
目前受影响的   
Owl Labs Meeting Owl版本：  
  
Owl Labs Meeting Owl 5.2.0.15  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/JVDECnNjedGVpoJMz3uW6z4rwwr0GJK5GwTjjMX8HdkwxuFiavhibvca4qAlXTKCaE6YGkZibSKEebNtAC56WAeNtibxuAjPgSAJ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/qE9MKluetOlD8gpGKew1L3bpxQxia8sSu6bicyAqpRpICVLyPe0q1KBPcqxTdGsXVKuM4bZEYAqMXtWD9UKm7QmrDIADHSknIv/640?wx_fmt=svg "")  
  
5. **解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/anblvjPKYbMeTTBE04NJlC7xdHcTw0Zr2pw7oRyyyU1OcS1bxCDIicTTfULAxI3Nnsxp4DQrOfHEicHzybp6icibpcHM9168PpAZ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/SYeWkon6C6JqUEnNYf8gnGKoWbXBpu9W48RrnGlj4ia1vX8m9PvwR0icA3q8DTEbJZHje4bZ2KDUP5DJP7PRxvmxyXs3UEYMOR/640?wx_fmt=svg "")  
  
  
  
目前  
Owl Labs已在Meet Owl Pro 和 Whiteboard Owl版本 5.4.1.4中修复了CVE-2022-31460，受影响的用户可以选择升级更新到此版本。  
  
链接如下：  
  
https://support.owllabs.com/s/knowledge/Meeting-Owl-Pro-Software-Release-Notes?language=en_US  
  
https://support.owllabs.com/s/knowledge/Whiteboard-Owl-Software-Release-Notes?language=en_US  
  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/JVDECnNjedGVpoJMz3uW6z4rwwr0GJK5GwTjjMX8HdkwxuFiavhibvca4qAlXTKCaE6YGkZibSKEebNtAC56WAeNtibxuAjPgSAJ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/qE9MKluetOlD8gpGKew1L3bpxQxia8sSu6bicyAqpRpICVLyPe0q1KBPcqxTdGsXVKuM4bZEYAqMXtWD9UKm7QmrDIADHSknIv/640?wx_fmt=svg "")  
  
6. **时间轴**  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/anblvjPKYbMeTTBE04NJlC7xdHcTw0Zr2pw7oRyyyU1OcS1bxCDIicTTfULAxI3Nnsxp4DQrOfHEicHzybp6icibpcHM9168PpAZ/640?wx_fmt=svg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/SYeWkon6C6JqUEnNYf8gnGKoWbXBpu9W48RrnGlj4ia1vX8m9PvwR0icA3q8DTEbJZHje4bZ2KDUP5DJP7PRxvmxyXs3UEYMOR/640?wx_fmt=svg "")  
  
  
  
【  
-  
】  
202  
2  
年  
0  
6  
月  
10  
日   
安识科技  
A  
-T  
eam团队监测到漏洞公布信息  
  
【  
-  
】  
2  
02  
2  
年  
0  
6  
月  
10  
日   
安识科技  
A-Team团队根据漏洞信息分析  
  
【  
-  
】  
2  
02  
2  
年  
0  
6  
月  
10  
日   
安识科技  
A-Team团队发布安全通告  
  
