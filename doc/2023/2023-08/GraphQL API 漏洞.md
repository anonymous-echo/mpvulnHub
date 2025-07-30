#  GraphQL API 漏洞   
枇杷五星加强版  黑伞安全   2023-08-10 20:18  
  
GraphQL 漏洞通常是由于实现和设计缺陷而产生的。  
例如，内省功能可能会保持活动状态，使攻击者能够查询 API 以收集有关其架构的信息。  
  
GraphQL 攻击通常采用恶意请求的形式，使攻击者能够获取数据或执行未经授权的操作。  
这些攻击可能会产生严重影响，特别是如果用户能够通过操纵查询或执行  
CSRF 漏洞  
来获得管理员权限。  
存在漏洞的 GraphQL API 还可能导致  
信息泄露  
问题。  
  
在本节中，我们将了解如何测试 GraphQL API。  
如果您不熟悉 GraphQL，请不要担心 - 我们将随时介绍相关细节。  
我们还提供了一些实验室，以便您可以练习所学知识。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGpz1y6ZcHx9UGIh4yNKc9cr5gzCCF1jkt27SfzPiasicF0EBiaXMiaibxnNNEVBtTMx1m9QdcHjHo4mxfQ/640?wx_fmt=png "")  
#### 更多信息  
  
有关 GraphQL 是什么及其工作原理的完整入门知识，请参阅我们的[什么是 GraphQL](http://mp.weixin.qq.com/s?__biz=MzU0MzkzOTYzOQ==&mid=2247487763&idx=1&sn=4852635b8e39d174e1b89d9d4fda3956&chksm=fb029c4bcc75155ddc5750805f72139028960f5f9f58f92218f0a2c1862625ba1a51f40df90d&scene=21#wechat_redirect)  
  
 Web 安全学院页面。  
## 查找 GraphQL 端点  
  
在测试 GraphQL API 之前，您首先需要找到它的端点。  
由于 GraphQL API 对所有请求使用相同的端点，因此这是一条有价值的信息。  
#### 笔记  
  
本节介绍如何手动探测 GraphQL 端点。  
但是，  
Burp Scanner  
可以在扫描过程中自动测试 GraphQL 端点。  
如果发现任何此类端点，则会引发“已找到 GraphQL 端点”问题。  
### 通用查询  
  
如果您发送query{__typename}  
到任何 GraphQL 端点，它将{"data": {"__typename": "query"}}  
在其响应中的某处包含该字符串。  
这称为通用查询，是探测 URL 是否对应于 GraphQL 服务的有用工具。  
  
该查询之所以有效，是因为每个 GraphQL 端点都有一个名为 的保留字段，__typename  
该字段以字符串形式返回查询对象的类型。  
### 常见端点名称  
  
GraphQL 服务通常使用类似的端点后缀。  
测试 GraphQL 端点时，您应该考虑将通用查询发送到以下位置：  
- /graphql  
  
- /api  
  
- /api/graphql  
  
- /graphql/api  
  
- /graphql/graphql  
  
如果这些常见端点不返回 GraphQL 响应，您也可以尝试附加/v1  
到路径。  
#### 笔记  
  
GraphQL 服务通常会响应任何非 GraphQL 请求，并显示“查询不存在”或类似错误。  
在测试 GraphQL 端点时，您应该牢记这一点。  
### 请求方式  
  
尝试查找 GraphQL 端点的下一步是使用不同的请求方法进行测试。  
  
生产 GraphQL 端点的最佳实践是仅接受内容类型为 的 POST 请求application/json  
，因为这有助于防止 CSRF 漏洞。  
但是，某些端点可能接受替代方法，例如使用内容类型 的 GET 请求或 POST 请求x-www-form-urlencoded  
。  
  
如果您无法通过向公共端点发送 POST 请求来找到 GraphQL 端点，请尝试使用替代 HTTP 方法重新发送通用查询。  
### 初步测试  
  
发现端点后，您可以发送一些测试请求以更多地了解其工作原理。  
如果端点正在为网站提供支持，请尝试在 Burp 浏览器中浏览 Web 界面，并使用 HTTP 历史记录来检查发送的查询。  
## 利用未经净化的参数  
  
此时，您可以开始寻找漏洞。  
测试查询参数是一个很好的起点。  
  
如果 API 使用参数直接访问对象，则可能容易受到  
访问控制  
漏洞的影响。  
用户只需提供与该信息相对应的参数，就可能访问他们不应该拥有的信息。  
这有时称为不安全的直接对象引用 (IDOR)。  
#### 更多信息  
- 有关 GraphQL 参数的一般说明，请参阅  
参数  
。  
  
- 有关 IDOR 的更多信息，请参阅  
不安全的直接对象引用 (IDOR)  
。  
  
例如，下面的查询请求在线商店的产品列表：  
  

    #Example product query

    query {
        products {
            id
            name
            listed
        }
    }  
  
返回的产品列表仅包含列出的产品。  
  

    #Example product response

    {
        "data": {
            "products": [
                {
                    "id": 1,
                    "name": "Product 1",
                    "listed": true
                },
                {
                    "id": 2,
                    "name": "Product 2",
                    "listed": true
                },
                {
                    "id": 4,
                    "name": "Product 4",
                    "listed": true
                }
            ]
        }
    }  
  
根据这些信息，我们可以推断出以下信息：  
- 产品被分配一个连续的 ID。  
  
- 列表中缺少产品 ID 3，可能是因为它已被除名。  
  
通过查询缺失产品的 ID，我们可以获取其详细信息，即使该产品未在商店中列出，也未通过原始产品查询返回。  
  

    #Query to get missing product

    query {
        product(id: 3) {
            id
            name
            listed
        }
    }
    #Missing product response

    {
        "data": {
            "product": {
            "id": 3,
            "name": "Product 3",
            "listed": no
            }
        }
    }  
## 发现架构信息  
  
测试 API 的下一步是拼凑有关底层架构的信息。  
  
执行此操作的最佳方法是使用内省查询。  
Introspection 是一个内置的 GraphQL 函数，使您能够查询服务器以获取有关架构的信息。  
  
内省可帮助您了解如何与 GraphQL API 交互。  
它还可能泄露潜在的敏感数据，例如描述字段。  
### 利用内省  
  
要使用自省来发现架构信息，请查询该__schema  
字段。  
该字段在所有查询的根类型上都可用。  
  
与常规查询一样，您可以指定运行内省查询时要返回的响应的字段和结构。  
例如，您可能希望响应仅包含可用突变的名称。  
### 探究自省  
  
  
在生产环境中禁用内省是最佳实践，但并不总是遵循此建议。  
  
您可以使用以下简单查询来探测内省。  
如果启用内省，响应将返回所有可用查询的名称。  
  

    #Introspection probe request

    {
        "query": "{__schema{queryType{name}}}"
    }  
#### 笔记  
  
Burp Scanner 可以在扫描期间自动测试内省。  
如果发现启用了自省，则会报告“GraphQL 自省已启用”问题。  
### 运行完整的自省查询  
  
下一步是针对端点运行完整的内省查询，以便您可以获得尽可能多的有关底层架构的信息。  
  
下面的示例查询返回所有查询、突变、订阅、类型和片段的完整详细信息。  
  

    #Full introspection query

    query IntrospectionQuery {
        __schema {
            queryType {
                name
            }
            mutationType {
                name
            }
            subscriptionType {
                name
            }
            types {
             ...FullType
            }
            directives {
                name
                description
                args {
                    ...InputValue
            }
            onOperation  #Often needs to be deleted to run query
            onFragment   #Often needs to be deleted to run query
            onField      #Often needs to be deleted to run query
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type {
            ...TypeRef
        }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                }
            }
        }
    }  
#### 笔记  
  
如果启用内省但上述查询未运行，请尝试  
从查询结构中删除onOperation  
、onFragment  
和指令。onField  
许多端点不接受这些指令作为内省查询的一部分，并且通过删除它们通常可以使内省更加成功。  
### 可视化内省结果  
  
对内省查询的响应可能充满信息，但通常很长且难以处理。  
  
您可以使用  
GraphQL 可视化工具  
更轻松地查看架构实体之间的关系。  
这是一个在线工具，它获取内省查询的结果并生成返回数据的可视化表示，包括操作和类型之间的关系。  
### 使用 InQL  
  
作为手动运行内省查询并可视化结果的替代方法，您可以使用 Burp Suite 的 InQL 扩展。  
  
InQL 是一个 Burp Suite 扩展，可帮助您安全地审核 GraphQL API。  
当您向其传递 URL 时（通过提供实时端点链接或上传 JSON 文件），它会发出请求所有查询和突变的内省查询，并提供结构化视图以方便探索结果。  
#### 更多信息  
  
有关在 Burp Suite 中使用 InQL 的更多信息，请参阅  
在 Burp Suite 中使用 GraphQL  
。  
### 建议  
  
即使内省完全被禁用，您有时也可以使用建议来收集有关 API 结构的信息。  
  
建议是 Apollo GraphQL 平台的一项功能，服务器可以在错误消息中建议查询修改。  
这些通常用于查询稍微不正确但仍可识别的情况（例如，There is no entry for 'productInfo'. Did you mean 'productInformation' instead?  
）。  
  
您可以从中收集有用的信息，因为响应有效地泄露了架构的有效部分。  
  
Clairvoyance  
是一种使用建议自动恢复全部或部分 GraphQL 模式的工具，即使在禁用内省的情况下也是如此。  
这使得从建议响应中拼凑信息所花费的时间显着减少。  
  
您无法直接在 Apollo 中禁用建议。  
请参阅  
此 GitHub 线程  
以获取解决方法。  
#### 笔记  
  
Burp Scanner 可以在扫描过程中自动测试建议。  
如果找到有效的建议，Burp Scanner 会报告“GraphQL 建议已启用”问题。  
  
## 绕过 GraphQL 内省防御  
  
如果您无法为正在测试的 API 运行内省查询，请尝试在__schema  
关键字后插入特殊字符。  
  
当开发人员禁用自省时，他们可以使用正则表达式来排除__schema  
查询中的关键字。  
您应该尝试使用空格、换行符和逗号等字符，因为 GraphQL 会忽略它们，但有缺陷的正则表达式不会忽略它们。  
  
因此，如果开发人员仅排除了__schema{  
，则不会排除以下内省查询。  
  

    #Introspection query with newline

    {
        "query": "query{__schema
        {queryType{name}}}"
    }  
  
如果这不起作用，请尝试通过替代请求方法运行探测器，因为只能通过 POST 禁用内省。  
尝试使用 GET 请求或内容类型为 的 POST 请求x-www-form-urlencoded  
。  
  
下面的示例显示了通过 GET 发送的内省探测，其中包含 URL 编码的参数。  
  

    # Introspection probe as GET request

    GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D  
#### 笔记  
  
如果端点仅接受通过 GET 的内省查询，并且您想要使用 InQL Scanner 分析查询结果，则首先需要将查询结果保存到文件中。  
然后，您可以将此文件加载到 InQL 中，它将像平常一样进行解析。  
  
实验室  
  
执业者  
查找隐藏的 GraphQL 端点  
  
未解决  
## 使用别名绕过速率限制  
  
通常，GraphQL 对象不能包含多个同名属性。  
别名使您能够通过显式命名您希望 API 返回的属性来绕过此限制。  
您可以使用别名在一个请求中返回同一类型对象的多个实例。  
#### 更多信息  
  
有关 GraphQL 别名的更多信息，请参阅  
别名  
。  
  
虽然别名旨在限制您需要进行的 API 调用数量，但它们也可用于暴力破解 GraphQL 端点。  
  
许多端点都会有某种速率限制器来防止暴力攻击。  
某些速率限制器基于收到的 HTTP 请求数而不是在端点上执行的操作数来工作。  
由于别名有效地使您能够在单个 HTTP 消息中发送多个查询，因此它们可以绕过此限制。  
  
下面的简化示例显示了一系列别名查询，用于检查商店折扣代码是否有效。  
此操作可能会绕过速率限制，因为它是单个 HTTP 请求，即使它可能用于一次检查大量折扣代码。  
  

    #Request with aliased queries

    query isValidDiscount($code: Int) {
        isvalidDiscount(code:$code){
            valid
        }
        isValidDiscount2:isValidDiscount(code:$code){
            valid
        }
        isValidDiscount3:isValidDiscount(code:$code){
            valid
        }
    }  
  
实验室  
  
执业者  
绕过 GraphQL 暴力保护  
  
未解决  
## GraphQL CSRF  
  
跨站点请求伪造 (CSRF) 漏洞使攻击者能够诱导用户执行他们不打算执行的操作。  
这是通过创建一个恶意网站来伪造对易受攻击的应用程序的跨域请求来完成的。  
#### 更多信息  
  
有关 CSRF 漏洞的更多一般信息，请参阅  
CSRF 学院主题  
。  
  
GraphQL 可以用作 CSRF 攻击的载体，攻击者可以利用该漏洞创建漏洞，导致受害者的浏览器以受害者用户的身份发送恶意查询。  
### GraphQL 上的 CSRF 漏洞是如何出现的？  
  
如果 GraphQL 端点未验证发送给它的请求的内容类型并且未实现 CSRF 令牌，则可能会出现 CSRF 漏洞。  
  
application/json  
只要  
 内容类型经过验证，使用 内容类型的 POST 请求就可以防止伪造。  
在这种情况下，即使受害者要访问恶意网站，攻击者也无法使受害者的浏览器发送此请求。  
  
x-www-form-urlencoded  
但是，浏览器可以发送  
 替代方法（例如 GET）或任何内容类型为 的请求，因此如果端点接受这些请求，则可能会使用户容易受到攻击。  
在这种情况下，攻击者可能能够利用漏洞向 API 发送恶意请求。  
  
  
对于基于 GraphQL 的CSRF 漏洞  
 ，构建 CSRF 攻击和利用漏洞的步骤  
与“常规”CSRF 漏洞相同。  
有关此过程的更多信息，请参阅  
如何构造 CSRF 攻击  
。  
  
实验室  
  
执业者  
通过 GraphQL 执行 CSRF 攻击  
  
未解决  
## 防止 GraphQL 攻击  
  
为了防止许多常见的 GraphQL 攻击，请在将 API 部署到生产环境时执行以下步骤：  
- 如果您的 API 不适合公众使用，请禁用其内省。  
这使得攻击者更难获取有关 API 工作原理的信息，并降低了不必要的信息泄露的风险。  
  
有关如何在 Apollo GraphQL 平台中禁用自省的信息，请参阅  
此博客文章  
。  
  
- 如果您的 API 供公众使用，那么您可能需要启用内省。  
但是，您应该检查 API 的架构，以确保它不会向公众公开意外的字段。  
  
- 确保建议已禁用。  
这可以防止攻击者使用 Clairvoyance 或类似工具来收集有关底层架构的信息。  
  
您无法直接在 Apollo 中禁用建议。  
请参阅  
此 GitHub 线程  
以获取解决方法。  
  
- 确保您的 API 架构不会公开任何私有用户字段，例如电子邮件地址或用户 ID。  
  
### 防止 GraphQL 暴力攻击  
  
使用 GraphQL API 时有时可以绕过标准速率限制。  
有关示例，请参阅  
使用别名绕过速率限制  
部分。  
  
考虑到这一点，您可以采取一些设计步骤来保护您的 API 免受暴力攻击。  
这通常涉及限制 API 接受的查询的复杂性，并减少攻击者执行拒绝服务 (DoS) 攻击的机会。  
  
防御暴力攻击：  
- 限制 API 查询的查询深度。  
术语“查询深度”是指查询内嵌套的层数。  
严重嵌套的查询可能会对性能产生重大影响，并且如果被接受，可能会为 DoS 攻击提供机会。  
通过限制 API 接受的查询深度，您可以减少发生这种情况的可能性。  
  
- 配置操作限制。  
操作限制使您能够配置 API 可接受的唯一字段、别名和根字段的最大数量。  
  
- 配置查询可以包含的最大字节数。  
  
- 考虑对您的 API 实施成本分析。  
成本分析是图书馆应用程序在收到查询时识别与运行查询相关的资源成本的过程。  
如果某个查询的计算过于复杂而无法运行，则 API 会删除它。  
  
#### 更多信息  
  
有关如何在 Apollo 中实现这些功能的信息，请参阅  
此博客文章  
。  
### 通过 GraphQL 防止 CSRF  
  
为了专门防御 GraphQL CSRF 漏洞，请在设计 API 时确保以下几点：  
- 您的 API 仅接受通过 JSON 编码的 POST 查询。  
  
- API 验证所提供的内容是否与所提供的内容类型相匹配。  
  
- 该 API 具有安全的 CSRF 令牌机制。  
  
