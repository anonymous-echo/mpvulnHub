#  某科云连erp存在sql注入漏洞   
原创 Kokoxca安全  Kokoxca安全   2024-12-16 12:45  
  
0x01.技术文章仅供参考学习，请勿使用本文中所提供的任何技术信息或代码工具进行非法测试和违法行为。若使用者利用本文中技术信息或代码工具对任何计算机系统造成的任何直接或者间接的后果及损失，均由使用者本人负责。本文所提供的技术信息或代码工具仅供于学习，一切不良后果与文章作者无关。使用者应该遵守法律法规，并尊重他人的合法权益。  
  
0x02.指纹信息  
```
web.boby="管理中心 - Powered By chaosZ"
```  
  
0x03 源码分析  
  
SQL注入一些常见的审计参数：  
```
${}
select
insert
update
in
like
orderby
statement
createStatemen
PrepareStatemen
或者全局搜索+ “
```  
  
这一处注入比较简单就是拼接参数没有过滤然后触发sql。  
  
前面的就不用看了就是  
接收字符串data然后打印日志啥的，然后  
将传入的JSON字符串解析为 Map  
 对象，在往下走会发现存在?是不是看到有?以为是占位符预编译了，这里的?不是预编译而是三元运算符。详细是如果map.get("CargoOwner")==null为true，那么CargoOwner被赋值为空字符串""。否则，将执行map.get("CargoOwner").toString()。  
```
String CargoOwner = map.get("CargoOwner") == null ? "" : map.get("CargoOwner").toString();
```  
  
往下走是sql查询构建使用StringBuffer  
 拼接SQL语句  
```
    StringBuffer sql = new StringBuffer();
    sql.append("SELECT DISTINCT info.item_no AS ProductId, info.item_no AS ProductNum, info.item_name AS ProductName ");
    sql.append("FROM bd_item_basic info ");
    sql.append("LEFT JOIN dc_item_info dc ON dc.item_no = info.item_no ");
    sql.append("LEFT JOIN bd_item_brand brand ON brand.item_brand_id = info.item_brand_id ");
    sql.append("LEFT JOIN bd_item_cls cls ON cls.item_cls_id = info.item_cls_id ");
    sql.append("WHERE info.combine_sta = '3' ");

```  
  
在往下走就可以看到直接拼接了参数触发了  
sql  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aYLtCGDrJ116jEXFiawgcmiapa2V1Jdqycibib0quwjiaAh5q62R5a31MjCicMiaiaeqzTciaeVGSPXZoh38Nx9aWSGhg8g/640?wx_fmt=png&from=appmsg "")  
  
0x03 漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aYLtCGDrJ116jEXFiawgcmiapa2V1JdqycSkaGn3IwFbhhPHmKMpf3Nrel1oqkyMvZDCKydCxhx2P2ZgfEpyjMSA/640?wx_fmt=png&from=appmsg "")  
  
**想要获取漏洞payload的可以关注公众号回复“erp”获取。**  
  
