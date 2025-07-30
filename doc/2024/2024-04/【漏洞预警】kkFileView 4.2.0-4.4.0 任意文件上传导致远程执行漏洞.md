#  【漏洞预警】kkFileView 4.2.0-4.4.0 任意文件上传导致远程执行漏洞   
cexlife  飓风网络安全   2024-04-17 23:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3PsAicJvCEW6CggeAD2JLAwXqJtf3ibBAcO54YCzp2fqNDMGZNsdrts9Q/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述：**kkFileView是使用spring boot搭建的文件文档在线预览解决方案,支持主流办公文档的在线预览,kkFileView 4.2.0 到4.4.0-beta版本中文件上传功能存在zip路径穿越问题,导致攻击者可以通过上传恶意构造的zip包,覆盖任意文件,kkFileView预览功能中会调用Libreoffice将odt文件转换为pdf,过程中会调用uno.py,攻击者可通过覆盖uno.py文件可执行任意python代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3p07aYS7MgPVKM2UetRMAUjeMcvqUiaSLUd7C8SlMicX33SLia7QLnC7Nw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3GiafxUTeHn2CPp8eGVrVkhPyR7QJVkcibwLAkicFOGibYibicXrNWuEf7ukA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01azmpPC83Vze7znjViaRCk3vaXb8lhibn5xkmo0zsa6KJjZWwwc6Vd8xOMhClHvffglWCgwJDCvyqg/640?wx_fmt=png&from=appmsg "")  
  
**影响范围:**  
  
kkFileView[4.2.0, 4.4.0-beta]**修复方案:**开启file.upload.disable=true参数,禁用首页的上传文件,关闭演示入口**参考链接:**https://github.com/kekingcn/kkFileView/commit/421a2760d58ccaba4426b5e104938ca06cc49778  
  
