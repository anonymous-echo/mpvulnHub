#  思科 SSM 本地漏洞可用于修改任意用户的密码   
 网安百色   2024-07-19 19:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo6TLA19pviaCFfbrwwfDkd81KlLEPjVUhNmpUTv82EJhu2QnczPmf7nU0UicVQhD3icJZp2vicGaWur0w/640?wx_fmt=gif "")  
  
  
  
**思科修复了一个CVSS满分漏洞，可导致攻击者更改易受攻击的 Cisco Smart Software Manager On-Prem (Cisco SSM On-Prem) 许可服务器上包括管理员在内的任何用户的密码。**  
  
  
  
该漏洞还影响早于 Release 7.0 的 SSM On-Prem 服务器，即 Cisco Smart Software Manager Satellite (SSM Satellite)。作为一个 Cisco Smart Licensing 组件，SSM OnPprem 协助服务提供商和思科合作伙伴管理客户账户和产品许可。  
  
该严重漏洞的编号是CVE-2024-20419，是由 SSM On-Prem 认证系统中的一个未经验证的密码修改弱点引发的。成功利用该漏洞可导致未认证的远程攻击者在不了解原始凭据的情况下设置新的用户密码。  
  
思科解释称，“该漏洞是因为密码更改流程实现不当造成的。攻击者可通过向受影响设备发送构造 HTTP 请求的方式利用该漏洞。成功利用该漏洞可导致攻击者以受陷用户权限，访问 web UI 或 API。”  
<table><thead><tr class="firstRow"><td valign="top" style="border-color: rgb(29, 54, 82);background: rgb(221, 221, 221);" width="256"><p style="text-align:center;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="letter-spacing: 1px;font-size: 15px;"><strong><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;">Cisco SSM    On-Prem </span></strong><strong><span style="color: rgb(51, 51, 51);font-family: 宋体;">发布</span></strong></span></p></td><td valign="top" style="border-top-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left: none;background: rgb(221, 221, 221);word-break: break-all;" width="187"><p style="text-align:center;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="letter-spacing: 1px;font-size: 15px;"><strong><span style="color: rgb(51, 51, 51);font-family: 宋体;">首次修复发布</span></strong></span></p></td></tr></thead><tbody><tr><td valign="top" style="border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left-color: rgb(29, 54, 82);border-top: none;" width="276"><p style="text-align:left;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="font-size: 15px;letter-spacing: 1px;"><span style="color: rgb(51, 51, 51);font-family: Arial, sans-serif;">8-202206 </span><span style="color: rgb(51, 51, 51);font-family: 宋体;">及更早</span></span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);" width="187"><p style="text-align:left;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(51, 51, 51);font-size: 15px;letter-spacing: 1px;font-family:Arial, sans-serif;">8-202212</span></p></td></tr><tr><td valign="top" style="border-right-color: rgb(29, 54, 82);border-bottom-color: rgb(29, 54, 82);border-left-color: rgb(29, 54, 82);border-top: none;" width="276"><p style="text-align:left;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: rgb(51, 51, 51);font-size: 15px;letter-spacing: 1px;font-family:Arial, sans-serif;">9</span></p></td><td valign="top" style="border-top: none;border-left: none;border-bottom-color: rgb(29, 54, 82);border-right-color: rgb(29, 54, 82);" width="187"><p style="text-align:left;margin-bottom: 15px;margin-left: 5px;margin-right: 5px;text-indent: 0em;"><span style="color: #333333;font-size: 15px;letter-spacing: 1px;font-family:宋体;">不受影响</span></p></td></tr></tbody></table>  
思科表示目前并不存在针对受影响系统的应变措施，所有管理员必须升级至已修复发布，保护环境中易受攻击服务器的安全。思科产品安全事件响应团队 (PSIRT) 尚未发现公开的 PoC 利用或针对该漏洞的利用尝试。  
  
本月早些时候，思科修复了一个NX-OS 0day漏洞 (CVE-2024-20399)。自今年4月起，该漏洞就被攻击者以 root 身份在易受攻击的 MDS 和 Nexus 交换机上安装此前未知的恶意软件。4月份，思科还提醒称受国家支持的黑客组织利用了另外两个0day漏洞（CVE-2024-20353和CVE-2024-20359）。自2023年11月起，攻击者已利用这两个漏洞在名为 “ArcaneDoor” 的攻击活动中攻击全球政府网络的 ASA和FTD防火墙。  
  
  
 来源：代码卫士  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo6M60aLu6MNdy20VjcnyaGECz7d9mYhdbclWg7wibJsickPUrnmNyFcvsjSYUqq5OPVPEXfW1SwkXCw/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/1QIbxKfhZo57Spb4ibrib8VUZd2ibdF9wHbvr4RwYJ4H2z6571icFIdSZXIpNH2YfW16ETwHh3ict3gtpW3W2fJqDmw/640?wx_fmt=gif "")  
  
长按添加关注，为您保驾护航！  
  
  
