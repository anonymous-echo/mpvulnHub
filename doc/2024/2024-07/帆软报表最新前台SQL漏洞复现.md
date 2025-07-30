#  帆软报表最新前台SQL漏洞复现   
原创 莫大130  安全逐梦人   2024-07-26 21:40  
  
# 环境搭建  
  
从官网上下载环境  
```
https://www.finereport.com/product/download/redirect?version=windows_x64_10.0&token=ydxWtxnCPbX3
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjs5jLzYyvhQdXE8sXwyK8aHw60ib4TYYLUd70XFHTUMQ99bFZr7h0Uhg/640?wx_fmt=png&from=appmsg "")  
  
  
安装好后，将  
webapps  
目录中   
webroot目录  
 的复制到   
tomcat3  
 中的webapps目录中  
  
接着启动运行 tomcat  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjzaG4iavaaf9p2GWyvksKpKCeb6CGTicH24zC6ASN184iaTSZwpMSgYicuQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjTRN5nUXTQUKCc0HP3ibNiaeZ9Sib2ywR97CYGVBX4toJA1Ggy5lOrEVoQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjQ81GUqnU4C4tYlycpCm8GzYlFDvbbk4CdPIIuHGwLbj1r7Mzcs59Kg/640?wx_fmt=png&from=appmsg "")  
  
接着运行   
apache-tomcat-8.5.87\bin\startup.bat  
 就成功搭建环境了  
  
第一次运行 先访问   
http://127.0.0.1:8080/webroot/decision  
  要设置密码，默认内置和外置数据库  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjOpvjNTLs7qG0mmdeVHz2uHTfYThs7XibCKDicBbVTsiaYAVrpKSuWA21g/640?wx_fmt=png&from=appmsg "")  
# 本地测试报错  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjVcXiap3Fy94UDnwspcqiabj1Bzvgvw8jBSEGfRJAyvKRhyQ8o3GOF9Ow/640?wx_fmt=png&from=appmsg "")  
  
配置tomcat   
server.xml  
 添加   
relaxedQueryChars="[]|{}^&#x5c;&#x60;&quot;&lt;&gt;"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjbS7BNUXogfrvaIWoc4lSRicNfvS4KDduLC7TBFicczFCedHUfjRgqicgA/640?wx_fmt=png&from=appmsg "")  
#   
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjVvHDQ9ib3PuBQG22bv3RUaCeUmCqY0Z2WThGYNLckKekJMa2CKKgCCw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAj9PGyDFC1rTaG6X2xUUfy5N4RbjCZFju6C1NicQmNuomnHuOjB48ITYQ/640?wx_fmt=png&from=appmsg "")  
# 本地测试写webshell  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjSiaSicz0NMOBYfDP6wcukep3jIMFdbXM32kUvODrDTGS0HoCFGhOQQQw/640?wx_fmt=png&from=appmsg "")  
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAj5ggLEppCy4NzfRGOJmfKPCTAwvnUicuKGRFB3NlqYe5RUpsMicWLxv0Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAj6ayS9qMJzqk6Do8dU4Jictd6evgBX6Tedea3dOT9N0SS43ovLlMzYibA/640?wx_fmt=png&from=appmsg "")  
  
蚁剑进行连接，添加get参数?a=javax.script.ScriptEngineManager，蚁剑连接密码为b，连接类型选择JSPJS  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/vOGOib9z4Wz4gicqldZ1qNoV8SOkdf6PAjbLf6o88taaYZBpDnS1YcHGevJvJYibI7Yl4QlIP47tVM3PAT78WXiceg/640?wx_fmt=png&from=appmsg "")  
  
# 参考  
- https://y4tacker.github.io/2024/07/23/year/2024/7/%E6%9F%90%E8%BD%AFReport%E9%AB%98%E7%89%88%E6%9C%AC%E4%B8%AD%E5%88%A9%E7%94%A8%E7%9A%84%E4%B8%80%E4%BA%9B%E7%BB%86%E8%8A%82/  
  
- [https://mp.weixin.qq.com/s/AliftiLevjz5HB9uL0DOqQ](https://mp.weixin.qq.com/s?__biz=MzkzMDcxNzg4MA==&mid=2247483934&idx=1&sn=457f8a14383589233ee4a38ff0d4f7ec&scene=21#wechat_redirect)  
  
  
