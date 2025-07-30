#  VMware vCenter Server多个漏洞通告   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-06-26 21:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl6fELamI62574iaia9spOdLTVbQetxLxv411RcbrFu6vvyef9oDgsFvZzA/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
VMware vCenter Server多个漏洞  
  
**组件名称：**  
  
VMware vCenter Server  
  
**安全公告链接：**  
  
https://www.vmware.com/security/advisories/VMSA-2023-0014.html  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl643BgfHLwjFTepZicOgUKjh1qzSVAIkzSIGbN87TT3ficAm0ccDdiaMFTQ/640?wx_fmt=gif "")  
  
**组件介绍**  
  
VMware vCenter Server是一种虚拟化管理软件，它可以帮助企业管理和监控虚拟化基础架构。它提供了一个集中的管理界面，可以用来管理和监控多个VMware虚拟化主机和虚拟机，同时提供了高级功能，如自动化、负载均衡和高可用性。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl643BgfHLwjFTepZicOgUKjh1qzSVAIkzSIGbN87TT3ficAm0ccDdiaMFTQ/640?wx_fmt=gif "")  
  
**漏洞描述**  
  
  
近日，深信服安全团队监测到一则VMware官方发布安全补丁的通告，共修复了5个安全漏洞，其中包含5个高危漏洞的信息。  
  
<table><tbody><tr><td width="40" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;word-break: break-all;"><p style="margin-top: 0pt;margin-bottom: 0pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">序号</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">漏洞</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">名称</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">影响版本</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="94" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;word-break: break-all;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">严重等级</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td></tr><tr><td width="40" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">1</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">VMware vCenter Server缓冲区溢出漏洞(CVE-2023-20892)</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">8.0≤VMware vCenter Server&lt;8.0U1b,7.0≤VMware vCenter Server&lt;7.0U3m</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="114" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">高危</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td></tr><tr><td width="40" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">2</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">VMware vCenter Server释放重引用漏洞(CVE-2023-20893)</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">8.0≤VMware vCenter Server&lt;8.0U1b,7.0≤VMware vCenter Server&lt;7.0U3m</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="114" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">高危</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td></tr><tr><td width="40" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">3</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">VMware vCenter Server 越界写入漏洞(CVE-2023-20894)</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">8.0≤VMware vCenter Server&lt;8.0U1b,7.0≤VMware vCenter Server&lt;7.0U3m</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="114" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">高危</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td></tr><tr><td width="40" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">4</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;word-break: break-all;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">VMware vCenter Server 越界读取漏洞(CVE-2023-20895)</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">8.0≤VMware vCenter Server&lt;8.0U1b,7.0≤VMware vCenter Server&lt;7.0U3m</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="114" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">高危</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td></tr><tr><td width="40" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">5</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">VMware vCenter Server 越界读取漏洞(CVE-2023-20896)</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="131" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">8.0≤VMware vCenter Server&lt;8.0U1b,7.0≤VMware vCenter Server&lt;7.0U3m</span><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;"><o:p></o:p></span></p></td><td width="114" valign="top" style="padding: 0pt 5.4pt;border-top: none;border-right-width: 1pt;border-right-color: windowtext;border-bottom-width: 1pt;border-bottom-color: windowtext;border-left-width: 1pt;border-left-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;text-indent: 23.8pt;line-height: 28pt;"><span style="font-family: 微软雅黑;letter-spacing: 0.45pt;font-size: 11pt;">高危</span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl643BgfHLwjFTepZicOgUKjh1qzSVAIkzSIGbN87TT3ficAm0ccDdiaMFTQ/640?wx_fmt=gif "")  
  
**漏洞描述**  
  
  
**VMware vCenter Server缓冲区溢出漏洞(CVE-2023-20892)**  
  
该漏洞是由于vCenter Server在DCERPC协议的实现中包含越界读取，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行越界读取攻击，最终造成服务器拒绝服务。  
  
  
**VMware vCenter Server释放重引用漏洞(CVE-2023-20893)**  
  
该漏洞是由于vCenter Server在DCERPC协议的实现中包含释放后引用，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行越界读取攻击，最终在服务器上执行任意代码。  
  
  
**VMware vCenter Server 越界写入漏洞(CVE-2023-20894)**  
  
该漏洞是由于vCenter Server在DCERPC协议的实现中包含越界写入，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行越界写入攻击，最终可造成服务器拒绝服务。  
  
  
**VMware vCenter Server 越界读取漏洞(CVE-2023-20895)**  
  
该漏洞是由于vCenter Server在DCERPC协议的实现中包含越界读取，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行越界读取攻击，最终可造成绕过身份认证。  
  
  
**VMware vCenter Server 越界读取漏洞(CVE-2023-20896)**  
  
该漏洞是由于vCenter Server在DCERPC协议的实现中包含越界读取，攻击者可利用该漏洞在未授权的情况下，构造恶意数据执行越界读取攻击，最终可造成服务器拒绝服务。  
  
  
**影响范围**  
  
  
VMware vCenter Server是较为流行的虚拟机集群平台之一，由于其丰富的功能被广泛使用。可能受漏洞影响的资产广泛分布于世界各地，此次曝出的漏洞都是高危漏洞，涉及用户量大，导致漏洞影响力高。  
  
受影响的VMware vCenter Server版本：  
  
8.0≤VMware vCenter Server<8.0U1b,  
  
7.0≤VMware vCenter Server<7.0U3m  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl643BgfHLwjFTepZicOgUKjh1qzSVAIkzSIGbN87TT3ficAm0ccDdiaMFTQ/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://www.vmware.com/security/advisories/VMSA-2023-0014.html  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl643BgfHLwjFTepZicOgUKjh1qzSVAIkzSIGbN87TT3ficAm0ccDdiaMFTQ/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
**1.风险资产发现**  
  
支持对VMware vCenter Server的主动检测，可批量检出业务场景中该事件的受影响资产情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**参考链接**  
  
https://www.vmware.com/security/advisories/VMSA-2023-0014.html  
  
  
**时间轴**  
  
  
  
**2023/6/26**  
  
深信服监测到VMware vCenter Server官方发布安全补丁。  
  
  
**2023/6/26**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl6muBKhX87icAibRNonodXNjexYYaFbkksicUAxmCCiadtEZ95TBnbiabTKfQ/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yojwZ8OCYTX22Lr1MibUWl6H4PtIFhZUbDMxx0MZaODko6xfjYbLOlIGAYtWGC7uzTuKxkkXN7X6g/640?wx_fmt=jpeg "")  
  
  
  
