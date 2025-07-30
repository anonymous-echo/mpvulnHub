#  平板锅(Palo Alto)防火墙0day 漏洞分析及Exp   
 独眼情报   2024-11-20 07:42  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnRqibw3tpUKVREPB4zJ1Fa1C8OGJoIVbVHBpXHfDgwUHRphXZPalsqVNE18kXTVJwWFohqquuRuVug/640?wx_fmt=png&from=appmsg "")  
  
watchTowr的研究人员Sonny近期发布了一份技术分析报告，深入剖析了影响Palo Alto Networks下一代防火墙(NGFW)的两个零日漏洞。这两个漏洞编号为CVE-2024-0012和CVE-2024-9474，已引起包括美国网络安全和基础设施安全局(CISA)在内的多个网络安全机构的高度关注。CISA已将其列入已知漏洞目录，并要求联邦机构必须在12月9日前完成修复。  
  
CVE-2024-0012是PAN-OS管理Web界面中的一个认证绕过漏洞。根据Sonny的分析，该漏洞允许远程攻击者在无需认证的情况下获得管理员权限。研究人员详细说明了他们的分析方法，从仔细审查Nginx配置文件开始。  
  
Sonny在分析报告中指出："查看主要的Nginx路由配置文件/etc/nginx/conf/locations.conf时，发现了一处看似很小但影响巨大的变更。"  
```
add_header Allow "GET, HEAD, POST, PUT, DELETE, OPTIONS";
 if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|OPTIONS)$) {
   return 405;
 }
 
+proxy_set_header X-Real-IP "";
+proxy_set_header X-Real-Scheme "";
+proxy_set_header X-Real-Port "";
+proxy_set_header X-Real-Server-IP "";
+proxy_set_header X-Forwarded-For  "";
+proxy_set_header X-pan-ndpp-mode "";
+proxy_set_header Proxy "";
+proxy_set_header X-pan-AuthCheck 'on';


 # rewrite_log on;
 
 # static ones
@@ -27,6 +17,5 @@ location /nginx_status {
 location ~ \.js\.map$ {
   add_header Cache-Control "no-cache; no-store";
   proxy_pass_header Authorization;
+  include conf/proxy_default.conf;
   proxy_pass http://$gohost$gohostExt;
 }

```  
  
研究人员发现，在未打补丁的版本中，X-PAN-AUTHCHECK头部设置存在缺陷，这可能导致未经授权的用户访问本应受保护的端点。  
  
通过利用这个疏忽，研究人员找到了一个简单但破坏力极强的绕过方法：只需将X-PAN-AUTHCHECK HTTP头部设置为off，就能完全禁用认证机制。  
  
第二个漏洞CVE-2024-9474则允许恶意的PAN-OS管理员提升权限，以root身份执行命令。该漏洞存在于AuditLog.php文件中，由于用户输入未经proper过滤，导致可能遭受命令注入攻击。  
  
研究人员在负责写入审计日志的函数中发现了一处关键性更改。Sonny演示了如何利用这个漏洞提升权限，他表示："用户竟然可以传入包含shell元字符的用户名到AuditLog.write()函数中，这些字符随后会被传递给pexecute()函数。"  
  
Sonny敦促管理员们迅速采取行动，并指出这个漏洞利用链的简单性："这两个漏洞能够出现在生产环境的设备中着实令人吃惊，更让人惊讶的是它们是通过Palo Alto设备底层那堆杂乱的shell脚本调用实现的。"  
  
为了给管理员留出打补丁的时间，watchTowr暂时没有公布完整的概念验证利用代码，但他们提供了一个Nuclei模板用于检测系统是否存在漏洞。  
  
另一方面，安全研究员Valentin Lobstein已经开发并发布了CVE-2024-0012和CVE-2024-9474的PoC利用代码，使得漏洞利用变得极其简单。基于watchTowr的分析，Lobstein开发的Go语言工具实现了攻击过程的自动化，用户只需输入目标URL即可。这个现成的利用工具增加了遭受攻击的风险，也凸显了及时修补易受攻击系统的紧迫性。  
  
Palo Alto Networks已在PAN-OS 10.2.12-h2版本中修复了这些漏洞。  
>   
> watchTowr详细分析：https://labs.watchtowr.com/pots-and-pans-aka-an-sslvpn-palo-alto-pan-os-cve-2024-0012-and-cve-2024-9474/  
  
>   
> nuclei检测模板：https://github.com/watchtowrlabs/palo-alto-panos-cve-2024-0012  
  
>   
> Exp利用代码：https://github.com/Chocapikk/CVE-2024-9474  
  
>   
> 请合法合规使用，任何乱用与本公众号无关，本公众号出于研究学习目的分享。  
  
  
  
  
