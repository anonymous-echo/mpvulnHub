#  Kinsing恶意软件利用新颖的Openfire漏洞   
 网络安全应急技术国家工程中心   2023-09-06 15:34  
  
Aqua Nautilus近日发现了一起新的攻击活动，该活动利用今年5月披露的Openfire漏洞（CVE-2023-32315）来部署Kinsing恶意软件和加密货币挖矿软件。该漏洞导致路径遍历攻击，从而授予未经身份验证的用户访问Openfire安装环境。随后，这让威胁分子得以创建一个新的管理员用户，并上传恶意插件。最终，攻击者可以全面控制服务器。我们在这篇博文中解释了这个漏洞、Kinsing的活动，并且量化了可能暴露于这个特定漏洞的实例的范围。比如说，结果表明我们专用的Openfire蜜罐在不到两个月的时间里遭到了1000多次攻击。  
# Openfire漏洞  
  
Openfire是一种实时协作（RTC）服务器系统，用作聊天平台，通过XMPP（可扩展消息传递和存在协议）发送即时消息。它旨在充当企业的内部即时消息服务器，支持50000多个并发用户，并为他们提供一条安全的独立通道，用于跨组织内不同部门之间的通信。  
  
今年5月，Openfire控制台上曝出了一个新的漏洞（CVE-2023-32315）。这个漏洞是在控制台中发现的，与安装环境中的路径遍历有关。该漏洞允许未经授权的用户利用已建立的Openfire配置中未经身份验证的Openfire安装环境。因此，威胁分子可以访问通常在Openfire管理控制台中受限制的管理设置文件。接下来，威胁分子可以选择向控制台添加管理员用户或者上传一个插件，最终便于全面控制服务器。  
# 剖析Kinsing活动  
  
这起Kinsing活动利用了这个漏洞，在运行时投放了Kinsing恶意软件和加密货币挖矿软件，试图逃避检测并获得持久性。下面的攻击流程图表明了这一点：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IWWxW2UsUdZicfM12Jse5MaaJF8bKn2tM1GibibSZRsX136vb2Bq4cvmvw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图1  
  
威胁分子扫描整个互联网查找Openfire服务器（示例如下），一旦找到了服务器，就会自动测试该服务器是否容易受到CVE-2023-32315的攻击。  
  
该漏洞允许创建能够上传插件的新管理员用户。在这起活动中，威胁分子使用该漏洞创建了一个新的管理员用户，并上传一个插件（cmd.jsp），该插件旨在部署主载荷：Kinsing恶意软件。  
  
如下面图2所示，威胁分子向user-create.jsp发送user create（用户创建）命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IqlM1ypbkSibaNF1XaPQNNrRr1CBsg6bLSGibDXrcX9xz7ciatWArJkPhQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图2. 攻击者发送请求，以便在Openfire服务器上创建新用户。  
  
请求由以下字段构成：  
  
• Create——create =%E5%88%9B%E5%BB%BA%E7%94%A8%E6%88%B7参数是一个html编码，转换为中文“创建用户”。  
  
• CSRF——在服务器端生成并与客户端共享的独特令牌，以防范CSRF攻击。使用GET方法时对令牌的不正确验证允许绕过验证。  
  
• Username——添加新创建的用户的名称。  
  
• Password——为新创建的用户添加密码。  
  
• Confirm——为新用户重新输入密码。  
  
• isAdmin——为新用户授予管理员权限。  
  
• Create ——发送上述数据以创建新用户。  
  
一旦成功创建了新用户，它使威胁分子能够完成Openfire管理面板的有效身份验证过程，从而作为经过身份验证的用户获得完整的访问权限。此外，由于用户是作为管理员创建的，因此这将授予威胁分子系统中的更高权限。  
  
接下来，威胁分子上传一个允许在服务器上执行web shell命令的恶意插件，如下图3所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IBs2Mdbe87HibFVV5zbyYLibpJbiaok7gdneTyAjqxVlsc7yzuD1EY0vEQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图3. 成功上传压缩后的Metasploit框架。   
  
威胁分子上传一个zip文件，这其实是一个Metasploit漏洞，旨在扩展cmd.jsp，使其能够在威胁分子的支配下启用http请求。这允许下载硬编码在插件中的Kinsing恶意软件。如下图4所示，该文件在VirusTotal（VT）中被两家供应商标记为恶意文件（后门/Kinsing）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IVAjnPa3txB5dia2Q3ZIaOUF14agYQKPaM71nQWyiayhhAuJ7dbSbwnqg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图4. 压缩后Metasploit文件的VirusTotal扫描。  
  
该zip文件包含恶意jar文件，但在VT中没有检测出来。  
  
在下面的图5中，你可以看到这个JAR文件的一个片段，更清楚地表明了其用途。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IvbohpUy38qVA2ja0Cb8NjYJThe8a9ic1due3qd5m1bKcz0tzgHxhWibw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图5. 攻击中主载荷的代码片段。  
  
这个插件包含一个名为cmd.jsp的Java类，它其实是后门，可以在服务器上下载文件和执行命令。  
  
接下来，C2服务器与恶意软件之间有频繁的联系。随后，下载一个新的shell脚本作为辅助载荷。  
  
该脚本创建一个cronjob（计划任务），并删除竞争性攻击，因此它旨在在服务器上实现持久性，如下面的图6和图7所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IDBMM6xTQZkfO6Tsh4Ccf7ReDibSicrEuo7PPibXw1nKKgL8YjtRYWHiboA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图6. 通过计划任务建立服务器持久性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IQ3VdpkzJU7McmPDB9eMU1vwBBu5fVRpt7Hfvz7nVaxNyyEkibY4Xzibw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图7. 消除旧的/竞争性的攻击。  
# 野外易受攻击的Openfire服务器  
  
由于全球各地的大型组织都在使用Openfire，我们对其在野外的漏洞暴露程度很好奇。我们查询了Shodan（IP搜索引擎），结果发现了6419台Openfire服务在运行的联网服务器。其中1383台（21.5%）无法联系上。剩余的5036台服务器中984台（19.5%）容易受到这个漏洞的攻击。  
  
在下面的图8中，你可以看到这些服务器的地理位置分布，看起来大多数服务器位于美国、中国和巴西。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7In5JYvugmjqkbgVtmw9eVqv5iaUnP1RgqTFPDGjddzBicibdXTaTMlVfWw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图8. Openfire漏洞实例地图。  
  
7月初，我们设置了一个Openfire蜜罐，它立即成为了攻击目标。如下图9所示，每天都有数十次针对Openfire漏洞的攻击。然而，大多数（91%）归因于上述的Kinsing活动。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IRIribhS3FcOonSUVb3JYbjj8GiagXHwyibiaX1Ko1ll3icgM2aVTzPZh9dA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图9. 7月1日至8月23日Openfire蜜罐攻击趋势。  
  
我们发现我们的蜜罐受到了两种不同类型的攻击。一种是上面广泛讨论的，它部署了web shell，使攻击者能够下载Kinsing恶意软件和加密货币挖矿软件，所有的攻击似乎都是相互关联的。第二种攻击涉及同一个Metasploit漏洞来部署web shell，但我们没有看到在这次攻击中使用了任何特定的工具。攻击者收集了有关系统的信息，但没有继续攻击。  
# 如何保护组织环境？  
  
随着新发现的漏洞数量不断增加，估计每年多达数万个，我们必须提高认识，并更加致力于维护资源。这篇博文强调了漏洞如何影响整个环境，将其置于险境之中。通过利用该漏洞，威胁分子获得了管理员用户的身份验证，从而能够在Openfire管理控制台中执行操作，并最终远程执行恶意命令。为了防范这些类型的攻击，我们建议遵循以下指导原则：  
  
1. 确保环境是最新的  
  
考虑到漏洞定期暴露，因此对更新和安全警报保持警惕至关重要。如果你发现其中一个实例易受影响，应根据经销商的指导原则，及时进行更新。我们构建了一个易受攻击的Openfire应用程序作为蜜罐，在下面的屏幕截图中，你可以看到我们的验证过程扫描新创建的容器镜像，以验证它是否容易受到上述漏洞的攻击。  
  
如图10所示，我们将扫描器设置为严重性评分高或严重的任何镜像都被标为失败。在这种情况下，唯一的漏洞是Openfire CVE-2023-32315，它未符合容器镜像。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IvAnfsG69ZwoGriaotv26DcpgdXbPaZpZcxJG64PfuIvEwCqIBNx8R3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图10. 检测到高危漏洞时，Aqua平台就构建失败。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IWQvgeMtU6icHcNcZiaMJib1DWxctn9BfKGWhLNibfM1smlrv1uibQ3QaElg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图11. Aqua平台中显示的漏洞细节。  
  
2. 认真配置环境  
  
避免使用默认设置，并确保密码遵循最佳实践。定期更新密文和密码可以进一步提高环境的安全性。  
  
3. 全面扫描环境以查找未知的威胁  
  
威胁分子正在逐步完善其策略，将其活动伪装成合法的行动，因此发现他们的行动成为一项艰巨的挑战。因此，运行时检测和响应解决方案在识别异常和发出恶意活动警报方面大有助益。我们在Aqua平台上的运行时保护模块检测到了Kinsing攻击，如下面的截图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IwKV0QLG4OkZF8V4h87A4V9zD5dGlwZ1WDiabyHUEdztfI9wu7EK3TOA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图12. Aqua平台中的攻击时间线。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IhAM3LMic2FiabhIkNWUpOkMOVNNRIPI6uNUustCA8BUny30D7F1oc29g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图13. 事件描述——Kinsing恶意软件进行直接联系，以下载加密货币挖矿软件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7I6mF3Sapuib0XVrDC7V5eVWPe3l52MlhkJFibFOKVVp566gFygQRRgRBw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
图14. Aqua平台中的漂移检测：文件kdevtmpfsi（门罗加密货币挖矿软）被下载到了容器中。  
  
IoC  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7IcpyK3BiaAa4D9whO02ND2ULC6fcjiaWu7XCu9fsCvGCNHkKkVGxicmwsQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7ISNcC2Bic01xT9CvkchqTOPCQgfZXmicxicnEia0bSX1ExgrT3hzcxUgYAQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ic1BfvEN4F4KHHSgicSRFr7ICt5s6iaK9xzN88II4Admia0Ckq8y7ynDzeU5ppsN2TV0sRcria3t525NQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**参考及来源：**  
  
https://blog.aquasec.com/kinsing-malware-exploits-novel-openfire-vulnerability  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
