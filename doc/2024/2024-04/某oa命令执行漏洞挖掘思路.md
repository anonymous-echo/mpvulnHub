#  某oa命令执行漏洞挖掘思路   
中铁13层打工人  Hacking黑白红   2024-04-08 23:53  
  
前段时间看到某系统爆出一个RCE，随后找到了源码对漏洞进行分析，并利用历史漏洞找到了其他突破点，进而找到新的漏洞。  
  
前段时间看到某系统爆出一个RCE，随后找到了源码对漏洞进行分析，并利用历史漏洞找到了其他突破点，进而找到新的漏洞。  
# 0x01 历史漏洞分析  
  
首先来看一个历史漏洞，Ognl表达式注入导致RCE，具体payload如下  
  
POST /common/common_sort_tree.jsp;.js HTTP/1.1  
  
Host: xx.xx.xx.xx  
  
Accept-Encoding: gzip, deflate  
  
Content-Length: 174  
  
Accept-Language: zh-CN,zh;q=0.8  
  
Accept: */*  
  
User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0 info  
  
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3  
  
Connection: close  
  
Cache-Control: max-age=0  
  
Content-Type: application/x-www-form-urlencoded  
  
  
rootName={%25Thread.@fe.util.FileUtil@saveFileContext(new%20java.io.File("../web/fe.war/123.jsp"),new%20sun.misc.BASE64Decoder().decodeBuffer("d2hvYW1p"))%25}  
  
首先该系统在未登录的状态下默认是无法直接访问一些jsp文件的  
  
在web.xml中可以看到对jsp的使用的过滤器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUub38q3icN6wOyDdsDXlJ76Jc2eLAvHbic8aroNCxYwTsM1Jj6cuMTHhw/640?wx_fmt=png&from=appmsg "")  
  
查看ControllerFilter5中的doFilter  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUliaomgazjHVvFTTeJfranDk2uVlJyK1aRge89DibUaXeAia3gxib1BQFLw/640?wx_fmt=png&from=appmsg "")  
  
发现会判断uri的结尾是否是.jsp，判断jsp是否在白名单列表里，如果不在则返回302重定向到登陆页面，可以可以利用tomcat特性使用;绕过，因为 在URL中遇到;号会将;xxx/中的**分号与斜杠之间的字符串以及分号本身**都去掉，当然也可以用url编码绕过，这点在这里不做过多分析。  
  
然后通过payload可以看到漏洞点在common_sort_tree.jsp，并且Ognl表达式通过rootName参数传递并执行，然后查看具体代码：![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUkaH58zN7xpCUqjCLETp7TzAbYy0CF6WkIsS1atKMHibEu2ppKhgcLFg/640?wx_fmt=png&from=appmsg "")  
  
  
通过查看该jsp文件可以看到rootName通过传参得到，然后传入builder.buildExp方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDU3ia6BxOsPX6qJjMNIs7M4Kk85pCDXpy4TXg2FFlTyEvcgHxHL1tPetw/640?wx_fmt=png&from=appmsg "")  
  
传入的语句首先会进行compiler生成一个列表，这个方法的主要功能是将输入的表达式进行编译，生成子表达式的列表，并在必要时替换原始表达式中的子表达式。该方法使用了一些标签和映射（startMap 和 stopMap）来辅助解析和替换。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUyHic99E5iaMFDibpBvJtRMsSicoAmKMmficMicpiayNrQpf4DNmB46iaqeGMLw/640?wx_fmt=png&from=appmsg "")  
  
然后在bean.xml中定义了一个parseMap 它表示了每个标签所对应的类方法，例如在payload中使用的是{%%}就对应使用的是objectValueParseImplbean 的标识符  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUs0ZEKKib2LPuCXRdzC8mOgfyxcsVvYK7iakWqqpGIXLclCyrkGKrGw1Q/640?wx_fmt=png&from=appmsg "")  
  
然后使用该类的实现作为 bean 的实例。.  
  
然后在初始化方法的时候，遍历parseMap，并且取前两个字符和后两个字符分别作为start(起始符)和stop(结束符)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUglnXrlNZ9LE6mPvTKPH7znlAp0KYawQ1vfgiaBpkVZbb3G3uN0t30TQ/640?wx_fmt=png&from=appmsg "")  
  
然后使用this.analyse.addParse，生成mapValue  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUh37QaHwvdXcjPhUm872nZGdYO6YpBa5aEsbzbzvz6btY667CFjNOwg/640?wx_fmt=png&from=appmsg "")  
  
然后使用tanalyse.analy进行分析并返回结果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDU7uxzU0UHQH8E76tJ5c7YkqQx0mBzaMOhPXuSOmNbTdV043fNnPlZ6A/640?wx_fmt=png&from=appmsg "")  
  
在analy中提取开始标签和结束标签和内容content  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUrCay4MQnBDR2JbHMuplAwNicutzMxIXybza3b6xV53yN134UoFbozSg/640?wx_fmt=png&from=appmsg "")  
  
然后再这个analy方法中，首选会确定需要调用的函数，使用this.mapValue通过stop也就是尾部标识符获取对应的类名，这里的this.mapValue是一个hashmap，然后使用最下面的p.load调用对应的方法。在该方法中然后调用了getValue，这里代码就省略了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUoC0a6VNeRseI425ZM9hjtzgf5bOZX2UkMiavX7Zr0WoIAkiacWfN5IhQ/640?wx_fmt=png&from=appmsg "")  
  
最终到达Ognl.getValue并执行Ognl语句造成RCE。  
# 0x02 其他漏洞发现  
  
了解完了历史漏洞触发的流程，可以发现漏洞的根本原因是最开始的builder.buildExp方法对参数过滤不严格造成的，如果按照这个思路去找漏洞，可以看看还有哪里调用了这个方法，并且参数是否可控。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUJicls51efBdxen3V1ZSCbQfvCnFYiaDbfEQpib5EHCSBYQiarHInVouJXg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUbVt5Kf40bjoSah1VvbQASfkp0INoXvDvkB6mypxwQubhrZ47YBhnzQ/640?wx_fmt=png&from=appmsg "")  
  
分别在jsp和jar包中搜索相关关键字，发现没有其他的引用。  
  
但是当我们回头看这个类中所定义的其他方法时，发现了其他和buildExp相似的方法  
  
例如build，他和buildExp除了方法名不一样内容都是一样的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUcYCf3KXZtrJ77a3UhJzBd7g31yxYNboHccdibYRAWhfBEETDZD0a56g/640?wx_fmt=png&from=appmsg "")  
  
包括其他方法，也有简介的调用了build方法，例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUia7Qfiaicffy4IibcRficcjujxE8VMYYicf8pfYTiabkpqxwO30BRDRorqbbQ/640?wx_fmt=png&from=appmsg "")  
  
所以这就大大扩大了我们的寻找范围，通过正则[\.| ]+builder\.build，找到了很多调用的地方，接下来就是看看哪些参数可控  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDU5iaEhfgSKrwjmiceNzUdmzAbu175G95BEy4hBZHUpJZoyI1RChA3DGWA/640?wx_fmt=png&from=appmsg "")  
  
这里找到其中一个，也就是上图搜索结果中的第一个：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDU8M2LzJzKCia8dO1BRtqFD7fibwgiaHxgdQ7lnECRK8VNkmY0Mz9sApAOQ/640?wx_fmt=png&from=appmsg "")  
  
但是这里的event会经过loginInvokeCtrl.formatLogic的格式化，在这个函数中，会在logic前后加上标识符，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUCNlgdtoQj8wvT7C6H4K1X4BSOJkwPznekyFE7Gr3JsJhDatCiba5fPg/640?wx_fmt=png&from=appmsg "")  
  
但这并不影响，因为在build中的compiler会一层一层剥离语句，首先会执行最内层的标签里的语句。  
  
接着继续追踪executeLogic看哪些地方调用了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUlNurdWRAx4LGNUJicIL6mOV2aDjicdLzFRZ6Ch1ARRI5uPyopKL5Dhpg/640?wx_fmt=png&from=appmsg "")  
  
在execute中，这两处均被调用了，并且参数时通过request.getParameter获得的，也是可控的。  
  
但是该语句是在一个if判断条件中，需要满足用户登录或者指定的methodName和springId，这两个值也是通过request.getParameter直接获取到的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUkbIYaPSgsq3iaEKZdDicpT4TNrVwQrSxJ0r5ZNvp5T3ic0rOEFLlcYSww/640?wx_fmt=png&from=appmsg "")  
  
然后继续向上追踪，终于找到了触发的地方doPost  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rf8EhNshONTdFCczrvibkppyTyOn9bXDUBo4dxcyFsAtPC4enkTkcwTd61MnplLWekoq4yB80Pr9vNorxKpjGVw/640?wx_fmt=png&from=appmsg "")  
  
同样找到了它的url映射路径。至此，请求路径，以及所有的请求参数都是可控的，且请求参数可以直接传递到具有漏洞的方法里。  
  
  
作者：  
中铁13层打工人  
  
来源：https://forum.butian.net/share/2701  
  
  
  
  
