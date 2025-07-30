#  【漏洞预警】Zyxel NAS 未授权文件上传限制不当可致远程代码执行   
cexlife  飓风网络安全   2024-06-05 18:38  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02xCDHibFyhUEtc2ndJwF4yM5gicpSWtuniaibTU0RNpwTsSYF9Yby8ezXw3EDuERYXhicN3xbEibzSRSEA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**Zyxel NAS326和NAS542设备中的CGI 程序file_upload-cgi中存在远程代码执行漏洞,未经身份验证的威胁者可通过将恶意设计的配置文件上传到易受攻击的设备导致执行任意代码。**修复建议:正式防护方案:**供应商已发布了CVE-2024-29972、CVE-2024-29973和CVE-2024-29974的补丁,受影响用户可升级到以下版本:NAS326设备:升级到V5.21(AAZF.17)C0NAS542设备:升级到V5.21(ABAG.14)C0**下载链接:**https://www.zyxel.com/global/en/support/download?model=nas326  
  
