#  【漏洞预警】Showdoc 未授权 SQL注入漏洞   
cexlife  飓风网络安全   2024-05-28 17:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02EDKrib8oc43pH328vD0g8eibXQ02cZsMrMVDZU6yEg9R9hp1mTpXUbdz0p17kBqT4v7IFRmEicDUxQ/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
  
ShowDoc V3.2.5 之前的版本中存在SQL注入漏洞，攻击者可通过此漏洞获取登录登录token并进入后台。进入后台后可结合反序列化漏洞，写入WebShell，从而获取服务器权限。**修复建议:****正式防护方案:**官方已经发布了修复补丁，请立即更新到安全版本:showdoc>=3.2.5**下载链接:**https://github.com/star7th/showdoc  
  
