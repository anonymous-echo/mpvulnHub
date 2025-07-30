#  【漏洞预警】Apache James未授权输入验证不当漏洞可导致拒绝服务   
cexlife  飓风网络安全   2025-02-11 14:43  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu03qJHtfQg3BpFENib0MAJlQ9iaQqNcL91nYrspenicPnXpfBib0calEr6Kz6oiagfgQicUbeplyKKrtqY3g/640?wx_fmt=png&from=appmsg "")  
  
****  
**James是属于Apache的一个开源项目,是Apache组织构建的一个可移植的、100%纯Java实现的企业级邮件服务器。**  
  
**漏洞详情:**  
  
Apache James发布安全公告,其中公开了一个输入验证不当漏洞,该漏洞与CVE-2024-34055类似,Apache James在IMAP字面量的滥用方面存在输入验证不当漏洞,无论是否经过身份验证的用户都可以利用这一点,这可能导致无限制的内存分配和非常长的计算,导致拒绝服务攻击。**修复方案:**厂商已发布补丁修复漏洞,建议下载相关补丁或联系厂商获取相关支持尽快更新至安全版本。**安全版本:**Apache James >= 3.7.6Apache James >= 3.8.2与此同时,请做好资产自查以及预防工作,以免遭受黑客攻击。**参考链接:**https://lists.apache.org/thread/1pxsh11v5s3fkvhnqvkmlqwt3fgpcrqc  
  
