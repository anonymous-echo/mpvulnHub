#  【漏洞通告】Apache Dubbo多个漏洞安全通告   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-12-18 20:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJEeSI7EwN5xxpnhVLcQXBaNvBoNcSicY1ClHfVcxl4qwkY51ZmCkB2Lw/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
Apache Dubbo多个漏洞安全通告  
  
**组件名称：**  
  
Apache Dubbo  
  
**安全公告链接：**  
  
https://lists.apache.org/thread/wb2df2whkdnbgp54nnqn0m94rllx8f77  
  
https://lists.apache.org/thread/zw53nxrkrfswmk9n3sfwxmcj7x030nmo  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJGLdLUbLibkHDqvThyPtlKA8l0Gtxs5t5pdYNSxfy7oibL3qjuhTFAVxw/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
Apache Dubbo是一款微服务框架，为大规模微服务实践提供高性能RPC通信、流量治理、可观测性等解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJGLdLUbLibkHDqvThyPtlKA8l0Gtxs5t5pdYNSxfy7oibL3qjuhTFAVxw/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞描述**  
  
  
近日，深信服安全团队监测到一则Apache Dubbo官方发布安全补丁的通告，共修复了2个安全漏洞，其中包含2个高危漏洞的信息。  
  
<table><tbody><tr><td width="77" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;word-break: break-all;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;"><strong>序号</strong><span style="font-size: 16px;"><strong><span style="font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></strong></span></p></td><td width="165" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;"><strong>漏洞名称</strong><span style="font-size: 16px;"><strong><span style="font-family: 仿宋_GB2312;"><o:p></o:p></span></strong></span></p></td><td width="200" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;"><strong>影响版本</strong><span style="font-size: 16px;"><strong><span style="font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></strong></span></p></td><td width="105" valign="top" style="padding: 0pt 5.4pt;border-width: 1pt;border-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;"><strong>严重等级</strong><span style="font-size: 16px;"><strong><span style="font-size: 16px;font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></strong></span></p></td></tr><tr style="height:72.3000pt;"><td width="57" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">1<span style="font-size: 15px;font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></p></td><td width="165" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;word-break: break-all;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">Apache Dubbo 反序列化漏洞(CVE-2023-46279)<span style="font-family: 仿宋_GB2312;font-size: 15px;"><o:p></o:p></span></p></td><td width="241" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">Apache Dubbo = 3.1.5<span style="font-size: 15px;font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></p></td><td width="105" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">高危<span style="font-family: 仿宋_GB2312;font-size: 15px;"><o:p></o:p></span></p></td></tr><tr style="height:111.6000pt;"><td width="77" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">2<span style="font-size: 15px;font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></p></td><td width="185" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">Apache Dubbo 反序列化漏洞(CVE-2023-29234)<span style="font-size: 15px;"><span style="font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></p></td><td width="241" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;"><p style="margin-top: 0pt;margin-bottom: 0pt;line-height: 28pt;padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;height: 72.3pt;color: rgb(110, 107, 107);font-size: 15px;">Apache Dubbo 3.2.x ≤ 3.2.4<o:p></o:p></p><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">Apache Dubbo 3.1.x ≤3.1.10<span style="font-family: 仿宋_GB2312;font-size: 15px;"><o:p></o:p></span></p><p style="margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;"><span style="font-family: &#34;Times New Roman&#34;;font-size: 15px;"> </span></p></td><td width="105" valign="top" style="padding: 0pt 5.4pt;border-left-width: 1pt;border-left-color: windowtext;border-right-width: 1pt;border-right-color: windowtext;border-top: none;border-bottom-width: 1pt;border-bottom-color: windowtext;word-break: break-all;"><p style="text-align:center;margin-top:0.0000pt;margin-bottom:0.0000pt;mso-pagination:widow-orphan;line-height:28.0000pt;mso-line-height-rule:exactly;">高危<span style="font-size: 15px;"><span style="font-size: 15px;font-family: &#34;Times New Roman&#34;;"><o:p></o:p></span></span></p></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJGLdLUbLibkHDqvThyPtlKA8l0Gtxs5t5pdYNSxfy7oibL3qjuhTFAVxw/640?wx_fmt=gif&from=appmsg "")  
  
**高危漏洞描述**  
  
  
**1.Apache Dubbo 反序列化漏洞(CVE-2023-46279)**  
  
Apache Dubbo中存在反序列化漏洞，攻击者利用该漏洞执行反序列化恶意代码，导致服务器失陷。  
  
  
**2.Apache Dubbo 反序列化漏洞(CVE-2023-29234)**  
  
Apache Dubbo中存在反序列化漏洞，攻击者利用该漏洞执行反序列化恶意代码，导致服务器失陷。  
  
  
**影响范围**  
  
  
Apache Dubbo 反序列化漏洞 (CVE-2023-46279)：  
  
Apache Dubbo = 3.1.5  
  
  
Apache Dubbo 反序列化漏洞 (CVE-2023-29234)：  
  
Apache Dubbo 3.2.x ≤ 3  
.2.4  
  
Apache Dubbo 3.1.x   
   
≤ 3.1.10  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJGLdLUbLibkHDqvThyPtlKA8l0Gtxs5t5pdYNSxfy7oibL3qjuhTFAVxw/640?wx_fmt=gif&from=appmsg "")  
  
**修复建议**  
  
  
**1.如何检测组件系统版本**  
  
（1）打开命令行或终端窗口。  
  
（2）在窗口中输入以下命令：  
  
mvn dependency:tree | grep dubbo  
  
（3）该命令将列出所有与Dubbo相关的依赖项，包括版本号。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJGLdLUbLibkHDqvThyPtlKA8l0Gtxs5t5pdYNSxfy7oibL3qjuhTFAVxw/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
官方已有可更新版本，建议受影响用户升级至最新版本。https://github.com/apache/dubbo/releases  
  
  
**参考链接**  
  
  
https://lists.apache.org/thread/wb2df2whkdnbgp54nnqn0m94rllx8f77  
  
https://lists.apache.org/thread/zw53nxrkrfswmk9n3sfwxmcj7x030nmo  
  
  
**时间轴**  
  
  
  
**2023/12/18**  
  
深瞳漏洞实验室监测到Apache Dubbo官方发布安全通告。  
  
  
**2023/12/18**  
  
深瞳漏洞实验室发布漏洞通告。  
  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJmgUu9oC2Kkr6xFia4zWoUaan0Px5C7O2k8ibP4Libd8ghmAHjzMOZNBxQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yA9lVwgYzuKuMQeZdZ4dHJuYQ2b1fiaQMLI54kwU6CpwmabJQRyhgTOhdHibrH4yoPgt7CkicxqiaIzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
