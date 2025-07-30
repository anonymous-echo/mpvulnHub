#  泥煤的，又一次RCE   
原创 石灰  富贵安全   2025-05-19 00:45  
  
### 这里略过其他功能点不能暴露太多，不然大师傅会干我。直接来到漏洞点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mtGcsnR1E3j586eXPxao2OcLx9bKibziarZqVL34hYWgibKZDLicXwMwwWIEXgTyWiapGicIoxKy976BuQ/640?wx_fmt=png&from=appmsg "")  
### 1.抓取该上传接口的数据包，上传http://100.100.100.200/latest/meta-data  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mtGcsnR1E3j586eXPxao2OWRqFmftuT9lkCcfQ7qPZJKCV6BRuu6P4TLxCcLGUn8oOQg8z6oLfmA/640?wx_fmt=png&from=appmsg "")  
### 2.发送数据包，获取到该url返回的fileid：f77ade68-b6b2-4aaf-a5bb-56e6a6cc7885  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mtGcsnR1E3j586eXPxao2OqBF87b8YibtvfDpPx8KZyX5ZwNs7GMlPiajA9CibRM1IZCD0GbEmKh93Q/640?wx_fmt=png&from=appmsg "")  
### 3.利用这里的fileid ，https://xxx.xxx.com/api/findocx/console/anydoc/file/加上fileid即可完成访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mtGcsnR1E3j586eXPxao2ORE6XwicHhSibS9qjzMIXWScsHlEUEDH4WWD7gMzPHY91wiaAHlvdqoKcQ/640?wx_fmt=png&from=appmsg "")  
### 4.进一步利用  
```
进一步利用，上传http://100.100.100.200/latest/meta-data/ram/security-credentials/，获取到fileid 再去拼接https://xxxx.xxxx.com/api/findocx/console/anydoc/file/fileid获取到账号名再重新上传http://100.100.100.200/latest/meta-data/ram/security-credentials/账号名，拿到fileid，再拼接https://XXXX.XXX.com/api/findocx/console/anydoc/file/fileid
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mtGcsnR1E3j586eXPxao2OZWiceWqqB1N4ok94RFslHSFwSn9ibDQT7JmxPlEKlZ85bkym2k2dJVqg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mtGcsnR1E3j586eXPxao2OovSdohW4gpbn6PZKFDD94rj8IzGiaYhXQhOmk6iaLYQrJzXQl1jEw2vQ/640?wx_fmt=png&from=appmsg "")  
  
  
