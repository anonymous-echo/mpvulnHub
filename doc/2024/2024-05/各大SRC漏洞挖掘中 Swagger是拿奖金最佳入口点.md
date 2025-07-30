#  各大SRC漏洞挖掘中 Swagger是拿奖金最佳入口点   
原创 马超  网安守护   2024-05-30 20:57  
  
### 阅读须知  
  
文章仅供参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！  
### 背景  
  
随着前后端分离架构的优势日益凸显，前后端分离应用的范围也日益扩大。如今，前后端分离已经成为互联网项目开发的业界标准。为了在实际开发中为前后端程序员提供统一的接口文档以便调试，衍生出了许多API接口文档和调试工具，比如swagger、docway、yapi、Web Api HelpPage等。结合之前挖掘的SRC和甲方工作中发现的问题案例，可以撰写一篇关于Swagger UI接口文档下测试的文章。  
### 认识Swagger  
  
Swagger是一个用于生成、描述、调用和可视化RESTful风格的Web服务的规范和完整框架。在金融机构的JAVA开发领域，JAVA一直拥有着重要的地位。作为JAVA服务端的主要框架之一，Spring将Swagger规范纳入了自身的标准，形成了Spring-swagger项目。因此，在实际测试环境中，基于Spring框架的Swagger UI接口展示及调试文档页面是最为常见的。让我们先来看一个Swagger UI页面，如下图所示，其中包含了诸如查询用户信息、上传文件等多个敏感操作的接口。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9Iq7hONK9TY1zodAYTREmPZyKlM6ia2iaAOOEibHCicCbcPzHJL2Y6OW0Ug/640?wx_fmt=png "null")  
  
  
在每个接口中都有详细的参数介绍，包括参数类型等信息。这意味着不再需要去模糊地尝试接口参数，而是可以直接根据参数类型构造参数即可完成任务。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9y8CgH4nKuW3ZcjQG3ia5nUaibXQmysr3Ylk6Rvy33YO7geE035ADlhWg/640?wx_fmt=png "null")  
  
### 发现Swagger  
  
1.使用JavaScript在网站的源代码中查找包含关键词"config"等的JavaScript文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax92iaNnhsQVgSWKpRMDmGpXllC4uZCmKGfuD0Q9dU7YiclEVDVLg67CmSg/640?wx_fmt=png "null")  
  
  
1.通过路径字典爆破，以下是搜集到的常见Swagger接口路径，亲测匹配率很高：  
  
•/swagger/  
•/api/swagger/  
•/swagger/ui/  
•/api/swagger/ui/  
•/swagger-ui.html/  
•/api/swagger-ui.html/  
•/user/swagger-ui.html/  
•/swagger/ui/  
•/api/swagger/ui/  
•/libs/swaggerui/  
•/api/swaggerui/  
•/swagger-resources/configuration/ui/  
•/swagger-resources/configuration/security/  
  
根据Swagger组件的特征，固定标题为：Swagger UI  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9G9Ap4e4iaVjKcckZx4Axib6BVH9b3DrbF6l683ibQ07Kibc03r4pqojoeA/640?wx_fmt=png "null")  
  
### 功能切入  
  
在找到Swagger UI页面后，我们应该快速浏览所展示的接口功能，并根据功能点按照高风险到低风险的顺序进行安全测试。常见的接口安全测试点包括：  
  
1.接口越权：尝试使用低权限用户的 token 进行水平越权查询修改其他用户信息，或者垂直越权尝试进行管理员操作。这可以通过尝试使用不同权限的用户 token 进行访问来测试。  
2.接口SQL注入：针对所有查询接口进行测试，尝试注入恶意的SQL代码以获取未授权的数据。  
3.接口未授权访问：重点关注管理员模块，尝试未授权访问对用户进行增删改查等操作的接口。  
4.任意文件上传：针对上传接口进行测试，尝试上传包含恶意代码的文件以执行任意代码。  
5.测试信息泄露：重点关注用户、订单等敏感信息的查询接口，以及可能泄露测试数据等的接口，尝试通过这些接口获取未授权的信息。  
### 案例：  
#### 1.越权  
  
在泄露的Swagger UI页面中发现了管理员添加用户模块以及分配权限模块。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9EWBib59Wtt9QdfA2qEtCjUpUDd1mCRHcB0qAFFdVrcsK3D5wOjjYeiaA/640?wx_fmt=png "null")  
  
  
有一个小细节需要注意，如果Swagger页面的地址不是直接拼接在域名之后，而是需要在域名后添加一些额外的路径，就像图中所示的情况，直接请求可能会导致404错误。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9TQGPYL93icQI3vxBmfmfSxicD2EKZOlj49GQJnVvnwqiaoAvlfIwf9skw/640?wx_fmt=png "null")  
  
  
因此，一般需要在域名后添加swagger-ui.html之前的URI地址（例如示例中的/api），才能够正常进行访问。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9RTk9Kmya81AlOVXJaplaibt8OribiaX6X3qsElsSJFzmKtcGc6DTNVJdA/640?wx_fmt=png "null")  
  
  
而在这种情况下，管理员添加用户接口也存在相同的情况。将curl指令复制出来，并添加上缺失的URI地址后，直接测试访问发现存在身份认证。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9jlGofFHGbIWm1uNCtA6ibTSEByUHRfvpKCa4baibhjRvz5tnsqz1OCSg/640?wx_fmt=png "null")  
  
  
但幸运的是，对应该Swagger的web应用提供了注册功能。我们尝试利用注册的低权限用户的cookie去访问，以查看是否可以进行垂直越权操作。将登录后的cookie添加在curl请求的-b参数中，再次访问，成功地进行了垂直越权，以管理员身份添加了用户。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9FuLcMp3BT7ZKibbp6eKtJYgfGPjrPqIOkSxYJpUwuRrjJVH8ntffWSw/640?wx_fmt=png "null")  
  
  
接着，利用泄露的权限管理接口，成功为用户添加了管理员模块权限。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9LWngfiauwRN3tMWjKQBicr07gePUS46bcCmu79OqolziaoEu4j9nIWo7Q/640?wx_fmt=png "null")  
  
#### 2.接口SQL注入  
  
根据查询接口的参数进行正常的SQL注入即可。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax94jNoUXp29hn1ljFic2fWicLNOLy8uuPSCoJWzH09G9vNxobtib0Db65jg/640?wx_fmt=png "null")  
  
#### 3.未授权访问  
  
许多开发者为了方便接口测试，取消了身份会话认证，这也导致了未授权访问问题变得十分频繁。可以想象一下，几十个功能接口就像是光溜溜地躺在你面前，等待着被发现和利用。  
  
最常见的情况就是未授权的查询接口，只需要简单地点击一下"Execute"按钮，所需的信息就会呈现出来。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9UTTeX1LnT0icgaSOlyB3ncuad0bniaykNicgKIAic1USxUqX4kKQxvbseA/640?wx_fmt=png "null")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9Ihwjn4T2Mr95bjDMHqfk0IZPibtMzpmicPDteFsLUqb2PvgjWav3YHIA/640?wx_fmt=png "null")  
  
#### 4.文件上传  
  
文件上传接口大多采用纯接口形式，没有前端校验，因此可以直接上传相应的测试脚本文件进行安全测试。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9qHsiaHDHDkI7baaQWTCJkYYX2bgXSbBZLa5EpGdyY2QyCIY5D9OIEXw/640?wx_fmt=png "null")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9Lo0P9xtQG8ykGWHibbrvnGynZ7Rp152XG95JY9y56IIc9yYbHDia6CfQ/640?wx_fmt=png "null")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9ia5qLsbpzIx27HcL4Ra9wxAUIrNOqxPMmE4QaDtN3KIoySpXXagtA3A/640?wx_fmt=png "null")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9auLxQP6eVLxjj0zS0ltO8EMkHv6G8p8b4zAefCoXuAiadu6vjRVaddQ/640?wx_fmt=png "null")  
  
#### 5.敏感信息泄露  
  
因为Swagger UI页面的泄露本身就属于最严重的敏感信息泄露，相比于接口中的敏感信息泄露，更多的情况是模块中的测试数据泄露。有时测试账号也可能拥有较高的权限，这增加了安全风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9GBCWqKbAvicUQvydrd5WUKic2QBNcJg890QaWM1AVW3x173IqhuudXdQ/640?wx_fmt=png "null")  
  
### 认证限制突破思路  
### 1.Swagger开启了页面访问限制  
  
如图所示，某个Swagger UI页面已经添加了登录认证。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9Svgic7ar05ysps7RKVoDkEEicQJrx4LgcHbzDwGslEylCooKTbiaeVZEQ/640?wx_fmt=png "null")  
  
  
除了尝试弱口令，还可以直接在swagger-ui.html之前的路径后添加/v1/api-docs，这样就可以访问接口了（其中v1代表接口的版本，你也可以尝试v2、v3等版本，也许会有意想不到的惊喜等着你~）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9rNysX4XdyW1iaZZr4ZOCeuTfRV8WHrE3RHMico8WaCGcJGoW47fiaoNBQ/640?wx_fmt=png "null")  
  
  
您可以以 JSON 格式查看 Swagger 文档，只需访问以下路径：  
```
/swagger/v1/swagger.json
```  
  
这将返回一个包含 Swagger 文档信息的 JSON 格式文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9ARiaXM7icbh0nJyqLkd70BqKh7fhlqKBiaQZONEWibdzQicYdqMhrnhE5vw/640?wx_fmt=png "null")  
  
### 2.Swagger开启了Authorize认证  
  
若Swagger在每个接口请求中开启了严格的Authorize认证，即使我们可以获取所有的接口路径，但因为没有身份会话，导致接口也无法执行成功。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax92BicvwyFbpJewQGjDiaqBYK4HDP9kxYia0htF5ujibapCFkPczGIeqdbvA/640?wx_fmt=png "null")  
  
  
针对接口开启了Authorize认证也不要放弃，我们应该努力尝试每一个接口。此时，可以尝试上传/下载文件、修改密码、登录等模块的接口，因为这些接口通常不需要或者容易出现身份认证的遗漏。当发现一个漏洞时，就能够打开局面，获取接口权限。  
  
例如，在某个Swagger页面中，虽然开启了Authorize认证，但通过查找发现了一个逻辑缺陷：修改用户账号密码时，直接根据用户账号就能够进行修改。利用这个缺陷，就可以直接重置管理员密码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9ib4YLu0C7ktYK3Z73Sy845SUue1qedCHf7cW2mTCjvE9NLB8Ok4gSBA/640?wx_fmt=png "null")  
  
  
在登录接口尝试登录后，发现可以成功登录并获取token，这是一个重要的发现。获取到token后，就可以使用该token尝试访问其他需要身份认证的接口，进而进行更深入的测试和攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9pibUcqlIOy2ZcBibu5Voa9NIE4Ysia1uURePNC7GLo5zOT4icmQicSMjvUA/640?wx_fmt=png "null")  
  
  
因为当前Swagger接口文档开启了Authorize认证，大部分接口无法直接调试。然而，如果获得了管理员的token，就可以对当前Swagger文档中的所有接口进行操作。这是一个重要的发现，因为管理员权限可以让您在接口文档中自由操作，进行各种测试和攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9tkvmFVmk1ric0edANNtYu0VuZVEgJr0MlfJNkusPhUSia6RicKdc5jOfg/640?wx_fmt=png "null")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WTOrX1w0s57L2HkqxnuK52JspPF63iax9CKNEoCkynW2yPclFtia9bHKiaQV7rG7f2gdSF0QWiaibZw2qHLYndicyD8w/640?wx_fmt=png "null")  
  
### 总结  
  
不管是挖掘SRC还是日常的渗透测试中，发现泄露的接口文档都可以帮助我们更好地进行漏洞挖掘。Swagger UI页面通常包含大量的测试接口，在进行上述漏洞总结点的安全测试时，可以尝试组合漏洞的利用。只要你足够细心，从接口测试到获取shell、内网漫游都是有可能的。  
  
**推荐书籍**  
  
  
  
  
  
