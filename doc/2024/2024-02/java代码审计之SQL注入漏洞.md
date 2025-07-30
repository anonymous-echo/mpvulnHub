#  java代码审计之SQL注入漏洞   
原创 goddemon  goddemon的小屋   2024-02-19 00:00  
  
## Part1 前言:  
  
开更文章了，开一个关于Java代码审计相关的系列。  
  
本来是想写成一本书的模式的,但是越写越发觉,篇幅太多,想了下还是每个专题单独写,而后最后汇总到一起。![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2HqYUSksxQth0x7SK2qgicUky3GvnkTGb5v7XrKY3lL7bGCarrKiarfXA/640?wx_fmt=png&from=appmsg "")  
慢慢写，基于笔者的理解抒写，如有问题，忘斧正。  
  
  
关于这个系列不会可能有些不会写修复方案,也不会写得特别细,这类文章外面太多了。  
  
重点是思路和思考  
## Part2 漏洞案例：  
  
还是基于案例来进行分享，这里的案例有些采用笔者审计过的系统案例非项目的来进行分析，有些没实际遇到过，但是有趣采用知识栈的思路去分析。  
  
  
对于sql说来还是有趣，笔者挖到的前台的SQL典型的基本上都是直接拼接导致的，基于框架的SQL 如mybatis的SQL有倒是有，但是几乎都是后台的，有和无区别似乎不是那么大。  
  
但是很多其他人审计不到的核心原因还是路由分析亦或是漏审文件导致的。  
  
其实SQL注入的核心在笔者看来只分为两类：  
  
直接拼接导致SQL注入  
  
框架体系导致SQL注入漏洞。  
  
当然也有些师傅还多了一种，预编译处理不当导致SQL注入漏洞，但其实在笔者看来 这个应该归类于修复不当导致的问题。  
  
这个不应该算作一类，所以笔者这里按两类去写。  
### 直接拼接导致的SQL注入  
  
这里写2个案例  
#### 案例1：  
  
某oa系统之前也分享过 直接拼接导致的SQL注入，该漏洞第一次发现是2022年8月份，给了1500![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2zDbrsCyHgc7ia8aVJWaIbb43S3k7bEB6mTKHHCJtErG4jcRcJic8R0UQ/640?wx_fmt=png&from=appmsg "")  
channelId 直接拼接导致的SQL注入，原理很简单  
  
开发本来是想用prepareStatement进行预编译的，但是问题在于直接预编译函数里面拼接SQL注入又有什么意义呢？![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2KBks7wUZVYewg0ABMBgnB3BB4OacSEVz6gTB4QiagWZriaXXGCcboTsg/640?wx_fmt=png&from=appmsg "")  
直接导致SQL注入  
#### 案例2：  
  
某oa sql注入漏洞  
  
笔者首次发现是在2022年5月左右，7月左右进行的提交![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2rW9pM0BfQaUYRS7Y8b5Kw2z2lzqJ5vjqeCCkSeqv1S07iaSt6m1StVg/640?wx_fmt=png&from=appmsg "")  
爆出来的某个sql 2024年爆出来的![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2o2lCqK2pk06S6Rgafe73S9CMiaqEh0xhGGgvUFSyPZibibR7S4zI9xyOw/640?wx_fmt=png&from=appmsg "")  
jc6/servlet/uploaddoc?key=readimage&sTablename=1&sKeyvalue=1*&sKeyvalue1=1&subPath=1   
  
漏洞原理：原理和上面没啥区别，一概而论就是参数直接拼接导致SQL注入。![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2Bdvm6qAZWOHf1fosuX0WPYAtcXXNprN5Kj4NicmXuG54CLcPhmKuLibQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2tVjib2uLjtHiaEVyWaqF4GhjX9icgtkkvyzgqr7EkVic9ibYgUeq9rGKIxw/640?wx_fmt=png&from=appmsg "")  
唯一区别这个是个union的 更方便利用。  
### 框架导致SQL注入：  
  
这里讲个比较经典的，就是mybatis框架的SQL注入漏洞问题。  
  
而至于Hibernate框架的SQL注入  
有研究的师傅可以知道其实本质上还是参数拼接导致的问题，所以在我个人理解看来应该归属于第一类。  
  
还是上面那句话，这种框架sql注入基本上遇到的后台占的可能性或许会更大。典型这三个模糊like，in，order by后SQL问题。![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2YUEbUBeoDfmYC1pSbey5CtkOeSmvzmUcIuEmgw9ialmPAqmCWptpa4w/640?wx_fmt=png&from=appmsg "")  
  
  
挖掘思路也简单，经典看mybatis mapper配置文件的写法
案例，笔者非项目审计过的前台的无，所以找不到记录,公司的项目 笔者不会拿出来写。  
  
所以写个大概的demo
大概demo如下，核心就是开发因为要使用like查询，order by查询，多值条件的查询。  
  
而使用该三个时，如果直接使用#  
  
会导致该无法正常使用，因而导致大部分开发会使用如下的写法  
  
进而导致SQL注入漏洞  
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mapper
        PUBLIC "-//mybatis.org//DTD Mapper 3.0//EN"
        "http://mybatis.org/dtd/mybatis-3-mapper.dtd">

<mapper namespace="cn.seaii.springboot.mapper.CategoryMapper">
    <select id="get" resultType="cn.seaii.springboot.pojo.CategoryM">
        select * from category_ where name= #{name} order by ${id} asc
    </select>
</mapper>



```  
## Part3 进一步分析与思考：  
  
这里抛出两个问题点  
### 问题一、如何自动化的审计上面提到的SQL注入？  
#### mybatis框架SQL注入自动化审计  
  
对于mybatis框架 Mapper文件的SQL注入漏洞，其实解决方法可以很简单  
##### 常见思路利用fortify审计工具：  
  
大家比较经典的就是利用Fortify去进行扫描，因为根据笔者使用看来，fortify对mapper文件的sql注入以及反射xss漏洞的效果确实还行，漏报率较低。  
  
缺点：速度慢，有可能受到其他代码的影响，导致项目无法扫描  
。  
  
这里关于fortify以及常见代码审计工具的原理不细讲了,后面再聊。  
##### 正则匹配思路：  
  
针对一个项目源码，反编译出所有相关源码，然后设置后缀为xml，然后利用正则匹配思路匹配$符号即可，进行分析扫描即可。  
#### 拼接SQL注入自动化审计：  
  
这种就没有配置文件的审计思路简单了。  
  
因为漏洞是可能存在任何代码里面,而有些地方 source压根没办法控制,还是写2个。  
##### fortify扫描：  
  
优点：误报率较低
缺点：漏报率较高。  
  
对于这块的SQL注入，如果在采用fortify这些审计工具去进行扫描，如果使用过的师傅会发觉，因为fortify的原理导致，因此可能会导致SQL注入存在漏报的情况。  
  
而且据笔者测试效果来看，漏报较多，如如果参数source点是从数据库取的情况，但数据库的这个参数点可以利用其他点控制这种情况，会导致漏报。  
##### 正则匹配思路：  
  
这里讲个最简单的，但是漏报率是比较低的，缺点就是误报率高。  
  
可以对常见的sink函数进行写一个规则进行匹配，匹配到后进行查看相关代码，进而实现快速挖掘的效果，第一个万户SQL注入就是基于这个去捡到的。  
  
这也是为什么能这么多文件的情况下仍然能尽量不漏的原因。  
### 问题二、是否是存在参数拼接就一定存在漏洞？  
  
答案肯定是不一定
在审计任何一个项目时，其实首先核心得明白代码的执行先后流程。  
  
比如，有些项目里面写了过滤器的情况下，过滤器里面写了自动化替换的情况下   
  
这种情况下就不要去思考审计相关漏洞,或者说去研究下有无可能绕过这个防护。  
  
如filter里面如果写了这种自动化替换呢?   
  
即对相关字符进行实体化编码
这种情况下哪怕存在SQL注入,也得需要去思考是否可以进行绕过。![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2F57mEvHYQkdyxGCQ7KzFqIF0fmpVw957VkKZPPzG07CrTtiblibOQicMA/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2SZID98XMGx3QY0InSlbXV3y3V3oPPRzmJu9G3ZeIAaYjGcalACrpBA/640?wx_fmt=png&from=appmsg "")  
  
## Part4 进一步拓展  
  
拓展一个吧
关于SQL注入,有时候不一定是SQL注入,或者说不一定要按照SQL注入的思路去打。  
  
如老生常谈的mssql情况下时,结合xp_cmdshell打拿shell思路。  
  
但其实说来也有趣,java常常搭配的数据库基本上都很少是mssql。  
  
关于上面的思路 笔者不在阐述,这里介绍另外一个知道的比较少的思路。  
### mybatis sql注入到ognl  
  
核心原理:
mybatis的配置思路有两种,第一种就是xml的思路配置,第二种就是利用注解的思路配置。  
  
出现问题就在于第二种注解配置的情况下,核心原因就是这种配置的sql支持ognl注入。  
  
因此如果mapper存在如下的关键词时
就得引起重视,这种情况下可以按照ognl的打法玩。  
```
@SelectProvider|@InsertProvider|@UpdateProvider|@DeleteProvider

```  
  
这种情况下可以按照ognl的思路打,当然得受到mybatis的版本限制,同时也受到ognl的版本限制,不同的版本有不同的玩法。  
  
具体的原理:可以看看这个老哥的   
  
这个老哥写的挺好的 不在额外阐述。  
  
[Mybatis 从SQL注入到OGNL注入](https://mp.weixin.qq.com/s?__biz=MzI4NTcxMjQ1MA==&mid=2247595613&idx=1&sn=d09c421531551aced4ea1a0b4b388716&scene=21#wechat_redirect)  
  
# END  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/BYtyQicN4iaC5Tr96ZkEETa719yV15kmS2BrNPZfg4sz6RTLILHDUUbpzOy1aoQemgrhEZgzhlzP95FnnDALcjgA/640?wx_fmt=jpeg&from=appmsg "")  
  
