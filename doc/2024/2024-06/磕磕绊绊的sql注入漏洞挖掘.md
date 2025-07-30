#  磕磕绊绊的sql注入漏洞挖掘   
中铁13层打工人  白帽子左一   2024-06-22 12:03  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
```
文章来源: https://forum.butian.net/share/3081
```  
# 0x01路由信息  
  
在审计.net时，首先要看的就是web.config，其中包括了网站的一些配置文件，包括数据库的连接信息和网站访问的路由。  
  
其中<httpHandlers> 元素是用于配置 HTTP 处理程序的一部分。HTTP 处理程序是处理传入 HTTP 请求的组件，它们可以用于响应特定类型的请求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZn4OPeqGLKZa05MNiaKqakSErQ5yXGuFnYYZwqhTqMQcAg0rEkNoDnrg/640?wx_fmt=png&from=appmsg "")  
  
verb表示请求的方式，例如POST，GET。*表示任何方式。  
  
path表示请求的文件，*表示通配符。  
  
validate表示指定是否要验证已配置的 HTTP 处理程序。  
  
type表示请求该文件时处理类的名称空间完整路径  
  
例如这里如果请求后缀是以.ajax就会访问Carpa.Web.Ajax.AjaxHandlerFactory，通过查看bin文件下，反编译Carpa.Web.dll文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZbL9eluyic1hetABXuqgeJd0MUGI9wya3sc41O5usiaY2kjpRqwicwCo4Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到AjaxHandlerFactory类继承了IHttpHandlerFactory，他的作用是对IHttpHandler进行管理。GetHandler返回实现IHttpHandler接口的类的实例  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZacOVjbvXs6kxr16c18xtfjWWnGnB6ukK3j34sYnPXTjwMibiaUkChRhQ/640?wx_fmt=png&from=appmsg "")  
  
这里首先会判断附加路径信息，长度是否大于2且是否包含/，这要调用的方法名methodName即为附加路径信息，Substring(int startIndex)指定了要开始提取子字符串的位置，该方法返回从 startIndex 位置开始直到原始字符串末尾的子字符串。这里的Substring(1)是为了去除最前面的/  
  
举个例子：  
  
例如在登录的时候，会发送这样一个请求包  
```
POST /A8TOP/CarpaServer/CarpaServer.LoginService.ajax/UserLogin HTTP/1.1
Host: 192.168.70.1
Accept: */*Accept-Language: zh-CNCookie: ASP.NET_SessionId=hqynyrsamsa1a5sfvwcqkeerContent-Type: application/json; charset=utf-8X-JSONFormat: truePragma: no-cacheReferer: http://192.168.70.1/A8TOP/ClientBin/CarpaClient.xap?v=392401900Accept-Encoding: gzip, deflateUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E)X-ClientType: SLJsonContent-Length: 198{"user":{"name":"admin","password":"123456","isChange":"","verificationCodeId":"","verificationCode":"","database":"002","lockNum":"err","userRank":NaN,"HardDiskNo":"errdisk","MacAddress":"errmac"}}
```  
  
实际就是请求LoginService类中的UserLogin方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZIMibH9pOyAvdpJYUDnHzqkec8GN1GpiaSY4Pv4AK8sdjSfrYiadvwGRrQ/640?wx_fmt=png&from=appmsg "")  
  
# 0x02鉴权分析  
  
在调用方法之前会首先通过CheckHasLogin来进行鉴权，当CheckHasLogin返回True就可以跳过throw new Exception  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZ2CY5BGHUIj6MPdliaGWa0ftAZQAHzaavE6HAntXvobeFgVcNooRQYcg/640?wx_fmt=png&from=appmsg "")  
  
  
接下来看看CheckHasLogin中是如何判断的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZicMibhbKFnHqVBzTnKMFicy6MpkFa6seoJ6vfdY8ibC6WZiaEiaSVUHzZ8hg/640?wx_fmt=png&from=appmsg "")  
  
这  
里会传入一个needLogin  
，当!needLogin  
符合条件是会直接return true，或者就是从context中获取session进行判断是否登录。  
  
而这里的needLogin时通过调用 IsDefined 方法来检查调用的类或方法是否定义了 NeedLoginAttribute 特性  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZIaib2tUA86ia85M07eSW6JA5IKRbGwC4JFCiaIsia8GcTjhbMv8Lg7HejQ/640?wx_fmt=png&from=appmsg "")  
  
  
这里提一下c#特性的解释，熟悉python的读者可以在某种程度上理解与装饰器有相似的目的。  
> C# 特性（Attribute）  
> **特性（Attribute）**是用于在运行时传递程序中各种元素（比如类、方法、结构、枚举、组件等）的行为信息的声明性标签。您可以通过使用特性向程序添加声明性信息。一个声明性标签是通过放置在它所应用的元素前面的方括号（[ ]）来描述的。  
> 特性（Attribute）用于添加元数据，如编译器指令和注释、描述、方法、类等其他信息。.Net 框架提供了两种类型的特性：预定义特性和自定义特性。  
  
  
例如下面这里，在类前面使用方括号 [] 表示的是类的特性（Attributes）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZJapw3J8A7VI113WodA1YUrSJhoz4dJ00KZgd1oMNf2XyJ35CuuZKBA/640?wx_fmt=png&from=appmsg "")  
  
至于为什么之前判断的是NeedLoginAttribute  
，是因为C#中定义一个类的特性，你需要创建一个类并继承自 System.Attribute  
 类，它的特性类通常命名为SomeNameAttribute  
的形式，其中SomeName  
是特性的名称，而Attribute  
是固定的后缀，用于表示这是一个特性类。  
在使用特性时，通常省略Attribute  
后缀，直接使用特性的名称即可。  
例如在这个系统中定义的就是NeedLoginAttribute  
实际使用中可以省略Attribute  
后缀  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZsL8F7A4mWewsk5On029icTHeO3Qr6G6ZhXbVJM0BWU5fAfJNl9Bzic8g/640?wx_fmt=png&from=appmsg "")  
# 0x03漏洞审计  
  
这里审计主要是审计未授权的漏洞，所以首先要筛选出类中不包含[NeedLogin]的类，这里可以先把所有文件都反编译成cs文件，然后使用python脚本筛选掉包含[NeedLogin]的字符串：  
```
import os
import re
import shutil

# 遍历文件夹
def traverse_directory(source_dir, dest_dir):
    for root, dirs, files in os.walk(source_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if not contains_need_login(file_path):
                copy_file(file_path, dest_dir)

# 检查文件内容是否包含[NeedLogin]
def contains_need_login(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            if '[NeedLogin]' in line:
                return True
    return False

# 复制文件到目标文件夹中，保留目录结构
def copy_file(file_path, dest_dir):
    relative_path = os.path.relpath(file_path, os.getcwd())
    dest_path = os.path.join(dest_dir, relative_path)
    dest_folder = os.path.dirname(dest_path)
    if not os.path.exists(dest_folder):
        os.makedirs(dest_folder)
    shutil.copy(file_path, dest_path)

# 源文件夹和目标文件夹路径
source_directory = 'source'
destination_directory = 'source2'

# 遍历文件夹并复制符合条件的文件
traverse_directory(source_directory, destination_directory)

```  
  
除此之外，在 Web Service 程序中，如果要使一个公共方法能够被外部访问和调用，需要为该方法添加[WebMethod]属性。只有添加了这个属性的公有方法才可以被外部访问，而没有添加该属性的方法则无法被访问。所以我们只查找添加了[WebMethod]属性的方法。  
## 漏洞寻找  
  
寻找sql注入漏洞，首先看看原本的sql语句是通过什么方法执行的，可以搜索关键字sql,dbHelper等关键字，发现这套程序里有三种执行sql语句的方法：一种是通过this.dbHelper.SelectFirstRow()执行，例如下图，这种是使用了预编译进行这种执行的，可以有效阻止sql注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZsIBOctjj6ErVHmicaXvTQOBonnSKIq3thHKDby1l0gU4gsTwC7PPCoA/640?wx_fmt=png&from=appmsg "")  
  
第二种方法是直接拼接sql语句，然后通过dbHelper.Select执行，例如下图，这种情况如果被拼接的参数可以通过传参获取且未进行过滤就可以造成sql注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZMsD8g1c94huiba2mqzZnEick7ctGKd8FLsuicPbWIE8CTxSMiccsqiakx3A/640?wx_fmt=png&from=appmsg "")  
  
第三种是通过string.Format  
格式化的方式来拼接sql注入，例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZrQJZYRXKuYGglsN0XQUvWsQcAIIO2a5Q7ibCZo18YnRAsbqgdqSeAHQ/640?wx_fmt=png&from=appmsg "")  
  
初次之外，该方法必须要被添加了[WebMethod]属性的方法直接或间接调用才可以直接通过 HTTP 协议进行调用。  
  
所以使用正则string sql = ".+?"[\s]*\+和string.Format\("SELECT.*?"\)匹配关键语句  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZNXIe1ib2p8n2CicWjaCVNMAJhT6uPbBP4ibhtwJAGKRou7X7sWqaBia0fQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZUUluoJPRMadUttVWsJ7ibB4j6lk5KT9wwQD6MfaPOZWmBiaOKdBvd2NA/640?wx_fmt=png&from=appmsg "")  
  
这  
里我  
们随便找一处  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZjUh9EeYDFfT4yvXbD6ZiaQ8eichKKlrpPLUVpOFahcqunicibtIPtgpxAg/640?wx_fmt=png&from=appmsg "")  
  
这里传递过来的参数直接拼接后去执行，但是正当我兴高采烈去发发包时，发现报错了，没有指定连接字符串  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZEndhV3jKn9y2k9urAiaXGa9hCcqCHgQny8fqOeutr1YziblwVONSqIpg/640?wx_fmt=png&from=appmsg "")  
## 失败原因  
  
这是怎么回事呢？经过继续研究发现他在通过AppUtils.CreateDbHelper()进行实例化对象dbHelper的时候，连接字符串是从UserInfo中获取的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZrIEKCuHeBbSF1gPuhHwIQaLeRIQgibjm69h3bm1CjicWibwk4jMFeAjaQ/640?wx_fmt=png&from=appmsg "")  
  
说明这是一个需要登陆以后才可以进行的sql注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZ0LKraHib1EnZCnDrhrgppq2V8hBDFE5h4LEsribfudK7ib4xiaZqcmh22A/640?wx_fmt=png&from=appmsg "")  
  
然后通过登录添加cookie后可以正常注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZf1pxzHYbEoLeiaJbGyXoicLStia6lM1XibXn2BWBaoHngsxX2yVicxjhNPA/640?wx_fmt=png&from=appmsg "")  
## 绝境逢生  
  
正当我决定到此为止时，突然看到CreateDbHelper方法下面还有一个重载的方法，他接受了一个database的字符串，这样是不是就代表有地方调用了重载的方法，从而不需要从UserInfo中获取连接字符串。或者是直接调用了DbHepler传入数据库名字。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZB9s9icbGiaCCSfFM9DK3jiaQ3kFjrk4d1ZPRuWKKLUphgs1aibWeqCCGXg/640?wx_fmt=png&from=appmsg "")  
  
所以我们将上面的python代码修改一下，将符合两种情况的文件再筛选出来  
```
def contains_need_login(file_path):
    with open(file_path, 'r', encoding="gb18030", errors='ignore') as file:
        for line in file:
            if re.findall('new DbHelper\(.+?\)\)', line):
                return False
            if re.findall('CreateDbHelper\(.+?\)\)', line):
                return False
    return True

```  
  
当然这里可以把[webmethod]加入筛选，但考虑到有些方法可能会通过间接调用，这样筛选可能会漏掉一些方法，所以暂时没有加入  
  
继续使用正则查找，找到这样一处，这里接受三个参数，第一个参数是数据库名字，第三个参数是一个json类型的字符串，并且json中的etypeid 或vipcardid的值拼接到sql语句中进行执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGCOT97ZSLhia4RRG8rYdCXZBmRjLqrkJAywjeJqHapicMdQcDr2SqRGuJc29APPhIHCr6kIwib6fliag/640?wx_fmt=png&from=appmsg "")  
  
最后没有携带任何cookie未授权成功执行。  
  
另外通过string sql = ".+?"[\s]*\+这样的查找方式也可以寻找到几处，有感兴趣的小伙伴可以亲自尝试一下。  
  
声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。**所有渗透都需获取授权**  
！  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前言漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，只需25，即可加入，如不满意，72 小时内可在 App 内无条件自助退款。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSGpTtick8dYImTUOcmaQWHRzkPIp7SwgncysYUIo0cKZAcHvXcMEBL5ZZEJCIpUP08SGOR8bnejDxQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSE3xxjQrLXjiaAWoqibdM1AFZ0uePzzUOG049bSjeEkbft1NfIm833fQ0ibIbW5IoE2ftnWoS3YxRPLg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
