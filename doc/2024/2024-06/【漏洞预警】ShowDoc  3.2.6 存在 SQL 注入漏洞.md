#  【漏洞预警】ShowDoc < 3.2.6 存在 SQL 注入漏洞   
cexlife  飓风网络安全   2024-06-04 23:44  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu037VoOR1GKCI3o4ZD7IqEZ0SSdBfRCadljaH9DeRrDCoLs04taFr1yXFv9x301WSDur1aFBMDSniaw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**ShowDoc是基于thinkPHP开发的开源文档管理系统,支持使用Markdown语法书写API文档、数据字典、在线Excel文档等功能,ShowDoc3.2.6之前版本存在sql注入漏洞,在Showdoc的/server/index.php?s=/api/item/pwd路径的item_id参数存在拼接执行逻辑，攻击者可利用sql注入爆破用户的user_token，进而窃取管理员凭据，获取所有API文档、附件及LDAP等配置信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu037VoOR1GKCI3o4ZD7IqEZ0JuNUzqkeVj89lWPVFsiaPayoOYEA8aSf4TZoIdpgsvvhjpf1wClmOwg/640?wx_fmt=png&from=appmsg "")  
  
**影响范围:**showdoc/showdoc(-∞, 3.2.6)**修复方案:**将组件showdoc/showdoc升级至3.2.6及以上版本https://www.showdoc.com.cn/  
  
