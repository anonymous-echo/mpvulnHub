#  漏洞精讲之SQL注入   
原创 Z1eaf  泷羽Sec-Z1eaf   2025-01-15 15:29  
  
# 一.SQL 注入相关概念  
### 1.什么是SQL  
  
结构化查询语言，简称SQL（语法统一）    SQL使我们有能力访问数据库  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rY3DHGcSQmRDLgloplWkGfcQibWibQKC1ia0cqAYXqnSGV04xHyEhG2TzeoLIKzmHDV8FYFvCjDRRay2tAyic4KIzg/640?wx_fmt=jpeg&from=appmsg "")  
### 2.什么是SQL注入  
  
攻击者通过在应用程序的输入中插入恶意SQL代码来执行未经授权的数据库操作。  
### 3.SQL注入原理和简单绕过原理  
  
SQL注入原理=在前端使用SQL语句传输到后端执行，获取数据库信息  
  
简单绕过原理 = 使用SQL语法的 -注释符号将SELECT语句的条件内容注释，实现简单绕过  
# 二.SQL语言语法  
## 1.SQL基础语言学习  
### （1）CREATE TABLE语句----用于数据库中创建表格  
```
CRATE TABLE 表名{
    列名称1 数据类型，
    列名称2 数据类型，
    列名称3 数据类型，
    ...
}

```  
### （2）INSERT INTO--插入数据  
```
  INSERT INTO 表名称 VALUES (值1, 值2,....);

```  
  
也可以指定插入数据的列  
```
INSERT INTO table_name (列1, 列2,...) VALUES (值1, 值2,....);

```  
### （3）SELECT -查询数据  
```
SELECT * FROM 表名称；

```  
  
也可以指定要查询数据的列；  
```
SELECT 列名称 FROM 表名称；

```  
  
注意  
：SQL语句对大小写不敏感，SELECT等效于select。另外，*是选取所有列的快捷方式。  
### （4）DISRINCT-去除重复值  
  
语法：  
```
SELECT DISTINCT 列名称 FROM 表名称；

```  
### （5）WHERE-条件过滤  
```
SELECT 列名称 FROM 表名称 WHERE 列 运算符 值;

```  
  
<table><thead><tr><th valign="top" style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0.02em;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;text-align: center;"><section><span leaf="">操作符</span></section></th><th valign="top" style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0.02em;text-align: left;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;"><section><span leaf="">描述</span></section></th></tr></thead><tbody><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">=</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">等于</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">!=或&lt;&gt;</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">不等于</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">&gt;</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">大于</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">&lt;</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">小于</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">&gt;=</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">大于等于</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">&lt;=</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">小于等于</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">BETWEEN</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">在某个范围里面</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">LIKE</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">搜索某种模式</span></section></td></tr></tbody></table>  
### （6）AND & OR 运算符  
  
AND 和 OR 可在 WHERE 子语句中把两个或多个条件结合起来。  
  
a.如果第一个条件和第二个条件都成立，则 AND 运算符显示一条记录。  
  
b.如果第一个条件和第二个条件中只要有一个成立，则 OR 运算符显示一条记录。  
  
AND语法：  
```
SELECT * FROM 表名称 WHERE 列 运算符 值 AND 列 运算符 值;

```  
  
OR语法  
```
SELECT * FROM 表名称 WHERE 列 运算符 值 OR 列 运算符 值;

```  
### （7）ORDER BY-排序  
  
默认排序为ASC顺序，DESC代表降序  
  
语法：  
```
SELECT * FROM 表名称 ORDER BY 列1,列2 DESC;

```  
### （8）UPDATE-更新数据  
  
UPDATE用于修改表内数据  
```
UPDATE 表名称 SET 列名称=新值 WHERE 列名称=某值;

```  
### （9）DELETE-删除数据  
  
语法：  
```
DELETE FROM 表名称 WHERE 列名称=值;

```  
### （10）DROP TABlE-删除表格  
  
DROP  TABLE语句适用于删除表（表的结构，属性以及索引）  
  
语法：  
```
DROP TABLE 表名称;

```  
## 2.SQL高级语言学习  
### （1）LIKE-查找类似值  
  
LIKE操作符用于在WHERE子句中搜索列中的指定模式  
  
语法：  
```
SELECT 列名/(*) FROM 表名称 WHERE 列名称 LIKE 值;

```  
### （2）IN – 锁定多个值  
  
IN 操作符允许我们在 WHERE 子句中规定多个值。  
  
语法：  
```
SELECT 列名/(*) FROM 表名称 WHERE 列名称 IN (值1，值2，值3);

```  
### （3）BETWEEN – 选取区间数据  
  
操作符 BETWEEN … AND 会选取介于两个值之间的数据范围。这些值可以是数值、文本或者日期。  
  
语法：  
```
SELECT 列名/(*) FROM 表名称 WHERE 列名称 BETWEEN 值1 AND 值2;

```  
  
查询相反的结果，可以使用NOT。  
```
SELECT 列名/(*) FROM 表名称 WHERE 列名称 NOT BETWEEN 值1 AND 值2;

```  
### （4）AS – 别名  
  
通过使用 SQL，可以为列名称和表名称指定别名（Alias），别名使查询程序更易阅读和书写。  
  
语法：  
  
表别名  
```
SELECT 列名称/(*) FROM 表名称 AS 别名;

```  
  
列别名  
```
SELECT 列名称 as 别名 FROM 表名称;

```  
  
注意  
： 实际应用时，这个 AS 可以省略，但是列别名需要加上 " "  
### （5）JOIN – 多表关联  
  
JOIN 用于根据两个或多个表中的列之间的关系，从这些表中查询数据。  
  
有时为了得到完整的结果，我们需要从两个或更多的表中获取结果。我们就需要执行 join。  
  
语法：  
```
select 列名 from 表A INNER|LEFT|RIGHT|FULL JOIN 表B ON 表A主键列 = 表B外键列;

```  
  
<table><thead><tr><th valign="top" style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0.02em;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;text-align: center;"><section><span leaf="">类型</span></section></th><th valign="top" style="color: rgb(89, 89, 89);font-size: 14px;line-height: 1.5em;letter-spacing: 0.02em;font-weight: bold;background-attachment: scroll;background-clip: border-box;background-color: rgb(240, 240, 240);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;text-align: center;"><section><span leaf="">描述</span></section></th></tr></thead><tbody><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">JOIN</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">如果表中至少有一个匹配，则返回行</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">INNER JOIN</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">内部链接，返回两表中匹配的行</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">LEFT JOIN</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">即使右表中没有匹配，也从左表返回所有的行</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">RIGHT JOIN</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">即使左表中没有匹配，也从右表返回所有的行</span></section></td></tr><tr style="color: rgb(89, 89, 89);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: left;background-position-y: top;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">FULL JOIN</span></section></td><td valign="top" style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;text-align: center;"><section><span leaf="">只要其中一个表中存在匹配，就返回行</span></section></td></tr></tbody></table>  
### （6）UNION-合并结果集  
  
union操作符用于合并两个或多个SELECT语句的结果集  
  
语法：  
```
SELECT 列名 FROM 表A
UNION
SELECT 列名 FROM 表B;

```  
### （7）NOT NULL-非空  
  
NOT NULL 约束强制列不接受 NULL 值。  
  
NOT NULL 约束强制字段始终包含值。这意味着，如果不向字段添加值，就无法插入新记录或者更新记录。  
  
语法：  
```
CREATE TABLE 表
(
列 int NOT NULL
);

```  
# 三.SQL注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rY3DHGcSQmRDLgloplWkGfcQibWibQKC1iaHKXDEf188A8icU2DIGibsmbwFq9eRbzJh4VQ0JmTNzTMMO59TiceCS5sg/640?wx_fmt=png&from=appmsg "")  
## 1.漏洞成因  
  
Web应用程序在接收相关数据参数时未做好过滤，将其直接带入到数据库中进行查询，而攻击者可以拼接执行构造的SQL语句，进行数据查询。  
## 2.漏洞危害  
- 数据库信息泄漏  
：数据库中存放的用户的隐私信息的泄露。  
  
- 网页篡改  
：通过操作数据库对特定网页进行篡改。  
  
- 网站被挂马，传播恶意软件  
：修改数据库一些字段的值，嵌入网马链接，进行挂马攻击。  
  
- 数据库被恶意操作  
：数据库服务器被攻击，数据库的系统管理员帐户被窜改。  
  
- 服务器被远程控制，被安装后门  
：经由数据库服务器提供的操作系统支持，让黑客得以修改或控制操作系统。  
  
- 破坏硬盘数据，瘫痪全系统  
。  
  
## 3. 常见的注入手法  
### （1）参数类型分类  
  
数字型：当输入的参数为整形时，如果存在注入漏洞，可以认为是数字型注入  
  
字符型：字符型注入刚好相反，当输入的参数是字符串时，称为字符型。字符型注入需要考虑引号闭合  
的问题  
### （2）注入手法分类  
#### a.联合注入（UNION注入）  
  
联合注入适用于有显示位的注入，即页面某个位置会根据我们输入的数据变化而变化  
##### 注入步骤(参考sqli-labs的第一关)  
1. 注入点判断 （注入参数，判断数字型还是字符型，若页面发生报错，说明后端对前端的数据输入没有很好的过滤，存在注入点）  
```
?id=1 and 1=2--+

```  
  
  
1. 判断当前表的字段数（通常使用 ORDER BY 进行试错，判断列数）  
```
?id=1 order by 3 --+

```  
  
  
1. 判断显示位（使用 UNION SELECT ,但前提是UNION SELECT前面的参数必须不存在，这样才能回显UNION SELECT 后面的输入）  
```
?id=-1 union select 1,2,3 --+ 

```  
  
  
1. 爆数据库的名字  
```
?id=-1 union select 1,2,database() --+ 

```  
  
  
1. 爆当前数据库的表名  
```
?id=-1 union select 1,2,group_concat(table_name) from information_schema.tables where table_schema=database() --+

```  
  
  
1. 爆表中的字段()  
```
?id=-1 union select 1,2,group_concat(column_name) from information_schema.columns where table_schema=database() and table_name='users'--+

```  
  
  
1. 爆相应字段的所有数据  
```
?id=-1 union select 1,2,group_concat(id,':',username,':',password) from users --+

```  
  
  
#### b.报错注入  
  
报错注入用在数据库的错误信息会回显在网页中的情况，如果联合查询不能使用，首选报错注入。       报错注入利用的是数据库的报错信息得到数据库的内容，这里需要构造语句让数据库报错  
##### 推荐3种报错注入的方法，查询语句和步骤 套用上面即可  
- **floor()、rand()、group by语句相结合的报错**  
  
原理：floor(rand(0)*2)的不确定性，可能为0也可能为1  
  
语句：  
  
```
select floor(rand(0)*2),count(*) from table gruop by floor(rand(0)*2) ;

```  
  
1.rand()函数： rand()返回0到1的随机数。 rand(0)返回一个固定的0到1的伪随机数。  
  
2、floor()函数： floor(x)返回小于或等于 x 的最大整数。  
  
3、group by语句： group by语句可以根据一个或多个列对结果集进行分组，在分组的列上我们可以使用 COUNT, SUM, AVG,等函数。  
  
SQL报错注入的应用：当count(*)、floor(rand(0))和group by x同时执行时，就会爆出duplicate entry错误。  
- **extractvalue()函数**  
  
原理：当使用extractvalue(xml_frag, xpath_expr)函数时，若xpath_expr参数不符合xpath格式，就会报错。  
  
而~符号(ascii编码值：0x7e)是不存在xpath格式中的， 所以一旦在xpath_expr参数中使用~~符号，就会产生xpath syntax error (xpath语法错误)，通过使用这个方法就可以达到报错注入的目的。  
  
语法：  
```
select 1 and extractvalue(xml_frag, xpath_expr);

```  
- **updatexml()函数**  
  
原理：当使用updatexml(xml_target, xpath_expr, new_xml)函数时，若xpath_expr参数不符合xpath格式，就会报错。  
  
语法：  
  
```
select 1 and updatexml(xml_target, xpath_expr, new_xml);

```  
#### c.布尔盲注  
  
布尔盲注，即在页面没有错误回显时完成的注入攻击。此时我们输入的语句让页面呈现出两种状态，相当于true和false，根据这两种状态可以判断我们输入的语句是否查询成功。  
##### 步骤  
  
用到ascii(),substr(),length(),concat(),exists()等函数  
  
  
efd3474708c75476c4d81ec5df27b98.jpg  
  
**一般布尔盲注，手工注入过于繁琐，一般建议使用工具**  
#### d.基于时间的盲注  
  
也叫延时注入。通过观察页面，既没有回显数据库内容，又没有报错信息也没有布尔类型状态，那么我们可以考虑用“绝招”--延时注入。  
  
**延时注入就是将页面的时间线作为判断依据，一点一点注入出数据库的信息**  
##### 方法：  
  
1.延时注入  
```
?id=1 and sleep(5) --+

```  
  
2.判断数据库名字长度  
```
?id=1' and if(length(database())<20,sleep(5),0) --+

```  
  
3.获取数据库名字  
```
?id=1' and if(ascii(substr(database(),1,1))= 115,sleep(5),0) --+

```  
  
注：if(expr1,expr2,expr3)       如果expr1的值为true，则返回expr2的值，如果expr1的值为false，则返回expr3的值。  
  
4.后面步骤与布尔盲注类似，不断尝试，得出所要数据  
#### e.HTTP头注入  
  
常见的sql注入一般是通过请求参数或者表单进行注入，而HTTP头部注入是通过HTTP协议头部字段值进行注入。  
  
**产生注入的条件：**  
- 能够对请求头消息进行修改  
  
- 修改的请求头信息能够带入数据库进行查询  
  
- 数据库没有对输入的请求信息做过滤  
  
#### f.宽字节注入  
  
宽字节注入准确来说不是注入手法，而是另外一种比较特殊的情况  
#### g.堆叠查询  
  
堆叠查询也叫堆叠注入，在SQL中，分号（;）是用来表示一条sql语句的结束。试想一下我们在 ; 结束一个sql语句后继续构造下一条语句，会不会一起执行？因此这个想法也就造就了堆叠注入。  
  
而union injection（联合注入）也是将两条语句合并在一起，两者之间有什么区别么？  
  
区别就在于union 或者union all执行的语句类型是有限的，可以用来执行查询语句，而堆叠注入可以执行的是任意的语句。  
#### h.二次注入  
  
二次注入漏洞是一种在Web应用程序中广泛存在的安全漏洞形式。相对于一次注入漏洞而言，二次注入漏洞更难以被发现，但是它却具有与—次注入攻击漏洞相同的攻击威力。  
###### 原理：  
  
二次注入就是由于将数据存储进数据库中时未做好过滤，先提交构造好的特殊字符请求存储进数据库，然后提交第二次请求时与第一次提交进数据库中的字符发生了作用，形成了一条新的sql语句导致被执行。  
  
