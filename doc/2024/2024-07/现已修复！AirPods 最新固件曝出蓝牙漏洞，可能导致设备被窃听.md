#  现已修复！AirPods 最新固件曝出蓝牙漏洞，可能导致设备被窃听   
 网安百色   2024-06-30 19:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
  
  
  
近日，苹果公司发布了 AirPods 的固件更新，但此版本固件曝出了一个严重漏洞，被追踪为 CVE-2024-27867，可能允许恶意行为者以未经授权的方式访问耳机。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39ibStR8gkRbu5UjvePeaWcYYfPMmxgjaZ7qibIoXV1YDNx0vYbIQy2T6Tfbt84aGcPKhB5NKNz3GKA/640?wx_fmt=webp&from=appmsg "")  
  
  
该漏洞影响 AirPods第二代及更高版本、AirPods Pro所有型号、AirPods Max、Powerbeats Pro 和 Beats Fit Pro。  
  
  
本周二（6月25日），苹果公司发布公告称：当你的耳机正在寻求配对设备的连接请求时，蓝牙范围内的攻击者可能会欺骗预期的源设备，并获得你耳机的访问权限。物理距离很近的攻击者可以利用这个漏洞窃听私人对话。  
  
  
Jonas Dreßler 最早发现并立刻报告了该漏洞。对此苹果公司表示，该漏洞现已通过改进状态管理得到解决。该漏洞在 AirPods 固件更新 6A326、AirPods 固件更新 6F8 和 Beats 固件更新 6F8 的一部分得到修补。  
  
  
两周前，iPhone 制造商推出了 visionOS（1.2 版）更新，共修复了 21 个缺陷，包括 WebKit 浏览器引擎中的 7 个缺陷。  
  
  
其中涉及到一个逻辑漏洞，被追踪为CVE-2024-27812，用户在使用设备处理网页内容时可能导致拒绝服务（DoS）。该公司表示，该漏洞已通过改进文件处理得到修复。  
  
  
安全研究员 Ryan Pickren 报告了这一漏洞，并将其描述为「世界上第一个空间计算黑客」，其可以绕过所有警告，在没有用户交互的情况下，用任意数量的 3D 动画对象强行填满你的房间。  
  
  
该漏洞利用了苹果公司在使用 ARKit 快速查看功能时未应用权限模型的漏洞，在受害者的房间里生成 3D 物体。更糟糕的是，这些动画对象在退出 Safari 后仍会继续存在，因为它们是由一个单独的应用程序处理的。  
  
  
对此，Pickren 表示：它甚至不需要人类点击这个标签就可以实现上述的情景。因此，JavaScript 的程序化点击（即 document.querySelector('a').click()）是没有问题的。这意味着我们可以在不与用户进行任何交互的情况下，启动任意数量的三维动画声音对象。  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  
