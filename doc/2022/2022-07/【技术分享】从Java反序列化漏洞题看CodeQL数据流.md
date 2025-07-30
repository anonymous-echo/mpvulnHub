#  【技术分享】从Java反序列化漏洞题看CodeQL数据流   
原创 SummerSec  安全客   2022-07-14 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Ok4fxxCpBb4hyPCH01qLmZlcYfLWt44zibkofckAGia4ODVZFib4Mofl8kaicJJ050vicv4YtVqzqa8moUtkeBbPDJA/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb4hyPCH01qLmZlcYfLWt44z0AO0MIECJChyVeecyX4qQRr8aIOFooqsSW7ML4M9ZW6icvKiar21nLOw/640?wx_fmt=png "")  
  
前言  
##   
  
本次实验项目源码来源之前我写的Shiro-CTF的源码  
https://github.com/SummerSec/JavaLearnVulnerability/tree/master/shiro/shiro-ctf  
 ，项目需要database文件上传到GitHub项目**learning-codeql**上。  
  
本文的漏洞分析文章  
一道shiro反序列化题目引发的思考  
 ，看本文之前看完这漏洞分析会更好的理解。但本文会从全新的角度去挖掘审计漏洞，但难免会有之前既定思维。如果你有兴趣和我一起交流学习CodeQL可以联系summersec#qq.com。  
## 找到可以序列化的类  
  
挖掘反序列化漏洞，首先得找到入口。可以反序列化的类首先肯定是实现了接口Serializable  
，其次会有一个字段serialVersionUID  
，所以我们可以从找字段或者找实现接口Serializable  
入手进行代码分析。  
1. TypeSerializable  
 类，在JDK中声明  
  
1. instanceof  
 断言  
  
1. fromSource  
 谓词判断来着项目代码排除JDK自带  
  
1. getASupertype  
 递归，父类类型  
  
```
import java/*找到可以序列化类，实现了Serializable接口 */from Class cl where     cl.getASupertype() instanceof  TypeSerializable    /* 递归判断类是不是实现Serializable接口*/    and     cl.fromSource()    /* 限制来源 */select cl
/* 查询语句 */
RefType.hasQualifiedName(string packageName, string className)
RefType
import java/* 找到实例化User的类 */class MyUser extends RefType{    MyUser(){        this.hasQualifiedName("com.summersec.shiroctf.bean", "User")    }}from ClassInstanceExpr cliewhere     clie.getType() instanceof MyUser
select clie
IndexController
User
IndexController
Base64
exeCmd
Tools#deserialize
Tools#exeCmd
LogHandler
exeCmd
exeCmd
commandStr
IndexController
request
bytes
request
source
sink
deserialize()#bytes
Tools#exeCmd
Loghandler
数据流
source
sink
sanitizers
additionalTaintStep
source
sink
IndexController
index
request
source
Tools#deserialize
bytes
sink
@kind
problem
path -problem
import DataFlow::PathGraph
import semmle.code.java.dataflow.TaintTracking
RemoteFlowSource
RemoteFlowSource
request->cookies->cookie->bytes
isAdditionTaintStep
LogHandler
Tools#exeCmd
LogHandler源码
Source
Sink
AdditionalTainStep
```  
