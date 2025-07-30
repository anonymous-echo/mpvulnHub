#  【漏洞预警】Jira身份验证绕过漏洞   
夜影实验室  锦行科技   2022-04-22 11:15  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruBPVte9dIoZM47cbYBXsgR4sAdWESOuDTSiaiaOThic1X4AhppKhKfa3WcjsXCbIibKDk5ibnAeuPndibHg/640?wx_fmt=gif "")  
  
  
**漏洞名称：**  
  
Jira 身份验证绕过漏洞  
  
**影响范围：**  
  
Jira：  
  
- Jira所有版本 < 8.13.18  
  
- Jira 8.14.x、8.15.x、8.16.x、8.17.x、8.18.x、8.19.x  
  
- Jira 8.20.x < 8.20.6  
  
- Jira 8.21.x  
  
   
  
jira Service Management：  
  
- Jira Service Management所有版本 < 4.13.18  
  
- Jira Service Management 4.14.x、4.15.x、4.16.x、4.17.x、4.18.x、4.19.x  
  
- Jira Service Management 4.20.x < 4.20.6  
  
- Jira Service Management 4.21.x  
  
**漏洞编号：**  
  
CVE-2022-0540  
  
**漏洞类型：**  
  
身份验证绕过  
  
**利用条件：**  
  
无  
  
**综合评价：**  
  
<利用难度>：低  
  
<威胁等级>：  
**高危**  
  
  
**#1**  
**漏洞描述**  
  
  
Jira 和 Jira Service Management 容易受到其 Web 身份验证框架 Jira Seraph 中的身份验证绕过的攻击。未经身份验证的远程攻击者可以通过发送特制的 HTTP 请求来利用此漏洞，以使用受影响的配置绕过 WebWork 操作中的身份验证和授权要求。  
  
  
**#2 解决方案**  
  
  
根据影响版本中的信息，排查并升级到安全版本。  
  
  
**#3 参考资料**  
  
  
https://confluence.atlassian.com/jira/jira-security-advisory-2022-04-20-1115127899.html  
  
https://nvd.nist.gov/vuln/detail/CVE-2022-0540  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruD6rSnJpSL57NHjuX79JSjjyYviaibNeS3xmGzPfoict6VdnvyuYEq6JdjQqre3WkicWWU7hjpicS2ByibQ/640?wx_fmt=gif "")  
  
**推 荐 阅 读**  
  
  
  
  
[喜讯！锦行科技3款产品入选广东省名优高新技术产品名单！](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489190&idx=1&sn=a8e0e5bb511dfa24480dee1854be52d0&chksm=9799ed03a0ee6415adcd0d4358427920823a013f2816afe1ec356eb69157a0a02dbbea4f0492&scene=21#wechat_redirect)  
  
  
  
[华为鲲鹏认证 | 国内首个欺骗防御安全平台性能再度提升](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247488804&idx=3&sn=0cfaf2cf82ae7193806432a045a3f881&chksm=9799ee81a0ee6797f12a48fc0e5335ac6200b4df30e2b3bf1913a59657f65559c9be78602707&scene=21#wechat_redirect)  
  
  
  
[政企必看 |《网络安全信息共享指南》公开征求意见](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247488650&idx=1&sn=c7a0795615493903a3de4ac35e9ff172&chksm=9799ef2fa0ee6639a906c50869c5cfc9d0fe4e99d524b3ed0c522b430cce4ac9a026cf9a8065&scene=21#wechat_redirect)  
  
  
