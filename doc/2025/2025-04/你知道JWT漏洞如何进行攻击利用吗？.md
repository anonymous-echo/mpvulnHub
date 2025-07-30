#  你知道JWT漏洞如何进行攻击利用吗？   
原创 夜风Sec  夜风Sec   2025-04-14 09:55  
  
## JWT攻击  
  
研究 JSON Web 令牌 (JWT) 的设计问题和处理缺陷如何导致网站容易受到各种高严重性攻击。由于 JWT 最常用于身份验证、会话管理和访问控制机制，这些漏洞可能会危及整个网站及其用户。  
  
![jwt-00](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3jmHm4U2DwRJEbvo2VSUtBZOISM1nNC65DTlH9XrIDN5GNWicb1w0aEg/640?wx_fmt=jpeg&from=appmsg "")  
  
jwt-00  
###  什么是JWT？   
  
JSON Web 令牌 (JWT) 是一种在系统之间发送加密签名 JSON 数据的标准化格式。理论上，它们可以包含任何类型的数据，但最常用于在身份验证、会话处理和访问控制机制中发送有关用户的信息（“声明”）。  
  
与传统会话令牌不同，服务器所需的所有数据都存储在客户端的 JWT 本身中。这使得 JWT 成为高度分布式网站的热门选择，因为用户需要与多个后端服务器无缝交互。  
#### JWT格式   
  
JWT 由 3 个部分组成：header，payload和signature。它们之间用点分隔，如下例所示：  
```
eyJraWQiOiI5MTM2ZGRiMy1jYjBhLTRhMTktYTA3ZS1lYWRmNWE0NGM4YjUiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJwb3J0c3dpZ2dlciIsImV4cCI6MTY0ODAzNzE2NCwibmFtZSI6IkNhcmxvcyBNb250b3lhIiwic3ViIjoiY2FybG9zIiwicm9sZSI6ImJsb2dfYXV0aG9yIiwiZW1haWwiOiJjYXJsb3NAY2FybG9zLW1vbnRveWEubmV0IiwiaWF0IjoxNTE2MjM5MDIyfQ.SYZBPIBg2CRjXAJ8vCER0LA_ENjII1JakvNQoP-Hw6GG1zfl4JyngsZReIfqRvIAEi5L4HV0q7_9qGhQZvy9ZdxEJbwTxRs_6Lb-fZTDpW6lKYNdMyjw45_alSCZ1fypsMWz_2mTpQzil0lOtps5Ei_z7mM7M8gCwe_AGpI53JxduQOaB5HkT5gVrv9cKu9CsW5MS6ZbqYXpGyOG5ehoxqm8DL5tFYaW3lB50ELxi0KsuTKEbD0t5BCl0aCR2MBJWAbN-xeLwEenaqBiwPVvKixYleeDQiBEIylFdNNIMviKRgXiYuAvMziVPbwSgkZVHeEdF5MQP1Oe2Spac-6IfA
```  
  
JWT 的标头和有效负载部分只是 base64url 编码的 JSON 对象。标头包含有关令牌本身的元数据  
，而有效负载包含有关用户的实际“声明”  
。例如，您可以从上面的令牌中解码有效负载以显示以下声明：  
```
 {    "iss": "portswigger",    "exp": 1648037164,    "name": "Carlos Montoya",    "sub": "carlos",    "role": "blog_author",    "email": "carlos@carlos-montoya.net",    "iat": 1516239022}
```  
  
在大多数情况下，任何有权访问令牌的人都可以轻松读取或修改这些数据。因此，任何基于 JWT 的机制的安全性都严重依赖于加密签名。  
#### JWT 签名   
  
颁发令牌的服务器通常通过对标头和有效负载进行哈希处理来生成签名  
。在某些情况下，它们还会加密生成的哈希值。无论哪种方式，此过程都涉及秘密签名密钥。此机制为服务器提供了一种方法来验证令牌自颁发以来是否未被篡改：  
- 由于签名直接从令牌的其余部分派生而来，因此更改标头或有效负载的单个字节会导致签名不匹配。  
  
- 如果不知道服务器的秘密签名密钥，就不可能为给定的标头或有效负载生成正确的签名。  
  
```
如果您想更好地了解 JWT 的构造方式，可以使用调试器jwt.io来试验任意令牌。
```  
###  JWT 与 JWS 和 JWE 对比   
  
JWT 规范实际上非常有限。它仅定义了一种将信息（“声明”）表示为可在双方之间传输的 JSON 对象的格式。实际上，JWT 并非真正用作独立实体。JSON Web 签名 (JWS) 和 JSON Web 加密 (JWE) 规范扩展了 JWT 规范，它们定义了实际实现 JWT 的具体方法。  
  
![jwt-01](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn39d2lfSP5mTCq6flR4t7cicqyibNdnz3jqBMuu8JBXPRbptvHsZHfvicKw/640?wx_fmt=jpeg&from=appmsg "")  
  
jwt-01  
  
换句话说，JWT 通常是 JWS 或 JWE 令牌。当人们使用术语“JWT”时，他们几乎总是指 JWS 令牌。JWE 非常相似，只是令牌的实际内容是加密的，而不仅仅是编码的。  
>   
> 为简单起见，在这些材料中，"JWT"主要指 JWS 令牌，尽管所描述的某些漏洞也可能适用于 JWE 令牌。  
  
###  什么是JWT攻击？   
  
JWT 攻击涉及用户向服务器发送修改后的 JWT，以实现恶意目标。通常，此目标是通过冒充已通过身份验证的另一个用户来绕过身份验证和访问控制。  
###  JWT攻击有什么影响？   
  
JWT 攻击的影响通常很严重。如果攻击者能够创建具有任意值的有效令牌，他们就可能提升自己的权限或冒充其他用户，从而完全控制他们的帐户。  
###  JWT攻击漏洞是如何产生的？   
  
JWT 漏洞通常是由于应用程序本身的 JWT 处理存在缺陷而引起的。与 JWT 相关的  
各种规范  
在设计上相对灵活，允许网站开发人员自行决定许多实现细节。这可能会导致他们意外引入漏洞，即使使用久经考验的库也是如此。  
  
这些实现缺陷通常意味着 JWT 的签名未得到正确验证。这使攻击者能够篡改通过令牌的有效负载传递给应用程序的值。即使签名经过了严格的验证，它是否真正值得信任在很大程度上取决于服务器的密钥是否保密。如果此密钥以某种方式泄露，或者可以被猜测或暴力破解，攻击者可以为任意令牌生成有效签名，从而破坏整个机制。  
###  如何在 Burp Suite 中使用 JWT   
  
学会如何在  
Burp  
中使用jwt:https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts  
###  利用有缺陷的 JWT 签名验证   
  
根据设计，服务器通常不会存储有关其发出的 JWT 的任何信息。相反，每个令牌都是一个完全独立的实体。这有几个优点，但也带来了一个根本问题 - 服务器实际上不知道令牌的原始内容，甚至不知道原始签名是什么。因此，如果服务器没有正确验证签名，就无法阻止攻击者对令牌的其余部分进行任意更改。  
  
例如，考虑包含以下声明的 JWT：  
```
{    "username": "carlos",    "isAdmin": false}
```  
  
如果服务器根据此username  
来识别会话，则修改其值可能会使攻击者能够冒充其他登录用户。同样，如果该isAdmin  
值用于访问控制，则可能为特权升级提供一个简单的载体。  
  
在前几个实验室中，您将看到这些漏洞在实际应用中可能出现的一些示例。  
#### 接受任意签名   
  
JWT 库通常提供一种验证令牌的方法和另一种仅解码令牌的方法。例如，Node.js 库jsonwebtoken  
有verify()  
和decode()  
。  
  
有时，开发人员会混淆这两种方法，只将传入的令牌传递给该decode()  
方法。这实际上意味着应用程序根本不验证签名。  
#### 接受无签名的令牌   
  
除其他事项外，JWT 标头还包含一个alg  
参数。该参数会告诉服务器使用哪种算法对令牌进行签名，以及在验证签名时需要使用哪种算法。  
```
{    "alg": "HS256",    "typ": "JWT"}
```  
  
这本身就存在缺陷，因为服务器别无选择，只能隐式地信任来自令牌的用户可控制的输入，而此时令牌根本没有经过验证。换句话说，攻击者可以直接影响服务器检查令牌是否可信的方式。  
  
JWT 可以使用多种不同的算法进行签名，但也可以不签名。在这种情况下，alg  
参数设置为none  
，表示所谓的"不安全的 JWT"。由于这种做法的明显危险，服务器通常会拒绝没有签名的令牌。但是，由于这种过滤依赖于字符串解析，因此有时您可以使用经典的混淆技术（例如混合大小写和意外编码）绕过这些过滤器。  
>   
> 即使令牌未签名，有效载荷部分仍然必须以尾随点终止。  
  
###  暴力破解密钥   
  
某些签名算法（例如 HS256 (HMAC + SHA-256)）使用任意独立字符串作为密钥。就像密码一样，这个密钥不能被攻击者轻易猜出或暴力破解，这一点至关重要。否则，他们可能能够使用他们喜欢的任何标头和有效负载值创建 JWT，然后使用该密钥通过有效签名重新签署令牌。  
  
在实施 JWT 应用程序时，开发人员有时会犯一些错误，例如忘记更改默认或占位符密钥。他们甚至可能复制并粘贴在线找到的代码片段，然后忘记更改作为示例提供的硬编码密钥。在这种情况下，攻击者使用  
众所周知的密钥的单词列表  
来暴力破解服务器的密钥可能轻而易举。  
#### 使用 hashcat 暴力破解密钥   
  
使用 hashcat 来暴力破解密钥。  
手动安装 hashcat  
，但它也已预安装并可在 Kali Linux 上使用。  
>   
> 如果您使用的是 Kali 的预构建 VirtualBox 映像而不是裸机安装程序版本，则可能没有分配足够的内存来运行 hashcat。  
  
  
你只需要一个来自目标服务器的有效且已签名的 JWT 和一个  
众所周知的秘密的单词表  
。然后，你可以运行以下命令，并将 JWT 和单词表作为参数传入：  
```
hashcat -a 0 -m 16500 <jwt> <wordlist>
```  
  
Hashcat 使用单词列表中的每个密钥对 JWT 中的标头和有效负载进行签名，然后将生成的签名与来自服务器的原始签名进行比较。如果任何签名匹配，hashcat 将以以下格式输出已识别的密钥以及其他各种详细信息：  
```
<jwt>:<identified-secret>
```  
>   
> 如果多次运行该命令，则需要包含--show  
标志来输出结果。  
  
  
由于 hashcat 在您的机器上本地运行并且不依赖于向服务器发送请求，因此即使使用庞大的单词列表，此过程也非常快。  
  
一旦确定了密钥，您就可以使用它为任何您喜欢的 JWT 标头和有效负载生成有效签名。有关如何在 Burp Suite 中重新签名修改后的 JWT 的详细信息，请参阅  
编辑 JWT  
。  
  
如果服务器使用极其弱的密钥，甚至可以逐个字符地进行暴力破解，而不是使用单词列表。  
###  JWT 标头参数注入   
  
根据 JWS 规范，只有alg  
标头参数是强制性的。但实际上，JWT 标头（也称为 JOSE 标头）通常包含几个其他参数。以下参数对攻击者特别感兴趣。  
- jwk  
（JSON Web 密钥）——提供一个代表密钥的嵌入式 JSON 对象。  
  
- jku  
（JSON Web 密钥集 URL）——提供一个 URL，服务器可以从中获取一组包含正确密钥的密钥。  
  
- kid  
（密钥 ID）- 提供一个 ID，当有多个密钥可供选择时，服务器可以使用它来识别正确的密钥。根据密钥的格式，这可能有一个匹配的kid  
参数。  
  
如您所见，这些用户可控制的参数分别告诉接收方服务器在验证签名时使用哪个密钥。在本节中，您将学习如何利用这些参数注入使用您自己的任意密钥（而不是服务器的密钥）签名的修改后的 JWT。  
#### 通过 jwk 参数注入自签名 JWT   
  
JSON Web 签名 (JWS) 规范描述了一个可选的jwk  
标头参数，服务器可以使用它来将其公钥以 JWK 格式直接嵌入到令牌本身中。  
>   
> JWK（JSON Web Key）是一种将密钥表示为 JSON 对象的标准化格式。  
  
  
您可以在以下 JWT 标头中看到此示例：  
```
{    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",    "typ": "JWT",    "alg": "RS256",    "jwk": {        "kty": "RSA",        "e": "AQAB",        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"    }}
```  
>   
> 如果您不熟悉"公钥"和"私钥"这两个术语，我们在算法混淆攻击材料中已经介绍过它们。有关更多信息，请参阅  
对称算法与非对称算法  
。  
  
  
理想情况下，服务器应仅使用有限的公钥白名单来验证 JWT  
 签名。但是，配置错误的服务器有时会使用嵌入在jwk  
参数中的任何密钥。  
  
您可以使用自己的 RSA  
 私钥对修改后的 JWT  
 进行签名，然后将匹配的公钥嵌入到jwk  
标头中，从而利用此行为。  
  
jwk  
虽然您可以在 Burp  
 中 手动添加或修改参数，  
但 JWT Editor 扩展  
提供了一个有用的功能来帮助您测试此漏洞：  
1. 加载扩展后，在 Burp  
 的主选项卡栏中，转到**JWT 编辑器键**  
选项卡。  
  
1. 生成新的 RSA 密钥。  
  
1. 向 Burp Repeater  
 发送包含 JWT  
 的请求。  
  
1. 在消息编辑器中，切换到扩展生成的**JSON Web Token**  
选项卡并根据需要  
修改  
令牌的有效负载。  
  
1. 单击**攻击**  
，然后选择**嵌入式 JWK**  
。出现提示时，选择新生成的 RSA  
 密钥。  
  
1. 发送请求来测试服务器如何响应。  
  
您也可以通过自己添加jwk  
标头来手动执行此攻击。但是，您可能还需要更新 JWT 的kid  
标头参数以匹配kid  
嵌入密钥的。扩展的内置攻击会为您完成此步骤。  
#### 通过 jku 参数注入自签名 JWT   
  
一些服务器不直接使用标头参数嵌入公钥jwk  
，而是允许您使用jku  
(JWK Set URL) 标头参数来引用包含密钥的 JWK Set。验证签名时，服务器会从此 URL 获取相关密钥。  
>   
> JWK Set 是一个 JSON 对象，其中包含代表不同键的 JWK 数组。您可以在下面看到一个示例。  
  
```
{    "keys": [        {            "kty": "RSA",            "e": "AQAB",            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"        },        {            "kty": "RSA",            "e": "AQAB",            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"        }    ]}
```  
  
此类 JWK 集有时会通过标准端点公开展示，例如/.well-known/jwks.json  
。  
  
更安全的网站只会从受信任的域获取密钥，但有时您可以利用 URL 解析差异来绕过这种过滤。我们在 SSRF 主题中 介绍了一些  
此类示例。  
#### 通过 kid 参数注入自签名 JWT   
  
服务器可能会使用多个加密密钥来签署不同类型的数据，而不仅仅是 JWT。因此，JWT 的标头可能包含kid  
(Key ID) 参数，这有助于服务器识别在验证签名时要使用哪个密钥。  
  
验证密钥通常存储为 JWK 集。在这种情况下，服务器可能只是查找与kid  
令牌相同的 JWK。但是，JWS 规范并未为此 ID 定义具体的结构 - 它只是开发人员选择的任意字符串。例如，他们可能使用该kid  
参数指向数据库中的特定条目，甚至是文件的名称。  
  
如果此参数也容易受到目录遍历的攻击，攻击者可能会强迫服务器使用其文件系统中的任意文件作为验证密钥。  
```
{    "kid": "../../path/to/file",    "typ": "JWT",    "alg": "HS256",    "k": "asGsADas3421-dfh9DGN-AFDFDbasfd8-anfjkvc"}
```  
  
如果服务器还支持使用  
对称算法  
签名的 JWT，则这种情况尤其危险。在这种情况下，攻击者可能会将kid  
参数指向可预测的静态文件，然后使用与该文件内容匹配的密钥对 JWT 进行签名。  
  
理论上，你可以对任何文件执行此操作，但最简单的方法之一是使用/dev/null  
，它存在于大多数 Linux 系统上。由于这是一个空文件，读取它会返回一个空字符串。因此，使用空字符串对令牌进行签名将产生有效的签名。  
>   
> 如果您使用的是 JWT 编辑器扩展，请注意，这不允许您使用空字符串对令牌进行签名。但是，由于扩展中的一个错误，您可以使用 Base64 编码的空字节来解决这个问题。  
  
  
如果服务器将其验证密钥存储在数据库中，则kid  
标头参数也是 SQL 注入攻击的潜在载体。  
#### 其他有趣的 JWT 标头参数   
  
攻击者可能还会对以下标头参数感兴趣：  
- cty  
（内容类型） - 有时用于声明 JWT 有效负载中内容的媒体类型。这通常会从标头中省略，但底层解析库可能仍然支持它。如果您找到了绕过签名验证的方法，可以尝试注入标头cty  
以将内容类型更改为text/xml  
或application/x-java-serialized-object  
，这可能会为  
XXE  
和  
反序列化  
攻击提供新的载体。  
  
- x5c  
（X.509 证书链） - 有时用于传递用于对 JWT 进行数字签名的密钥的 X.509 公钥证书或证书链。此标头参数可用于注入自签名证书，类似于上面讨论的jwk  
标头注入  
攻击。由于 X.509 格式及其扩展的复杂性，解析这些证书也可能引入漏洞。这些攻击的详细信息超出了这些材料的范围，但有关更多详细信息，请查看  
CVE-2017-2800  
和  
CVE-2018-2633  
。  
  
###  JWT 算法混乱   
  
即使服务器使用了您无法暴力破解的强密码，您仍然可以通过使用开发人员未曾预料到的算法对令牌进行签名来伪造有效的 JWT。这被称为算法混淆攻击。  
###  算法混淆攻击   
  
算法混淆攻击（也称为密钥混淆攻击）是指攻击者能够强制服务器使用与网站开发人员预期不同的算法来验证 JSON Web 令牌 (   
JWT  
 ) 的签名。如果处理不当，攻击者可能无需知道服务器的秘密签名密钥即可伪造包含任意值的有效 JWT。  
#### 对称与非对称算法   
  
JWT 可以使用多种不同的算法进行签名。其中一些算法（如 HS256 (HMAC + SHA-256)）使用"对称"密钥。这意味着服务器使用单个密钥来签名和验证令牌。显然，这需要保密，就像密码一样。  
  
![jwt-10](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3IoSroxWXkQM4UrAnWGicbZicoZfbkXiaibkoMyn4QlXpYMCSZUyKW5Hq4w/640?wx_fmt=jpeg&from=appmsg "")  
  
jwt-10  
  
其他算法（例如 RS256（RSA + SHA-256））使用“非对称”密钥对。该密钥对由一个私钥（服务器使用该私钥对令牌进行签名）和一个数学相关的公钥（可用于验证签名）组成。  
  
![jwt-11](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn35ANu1nWjNTjkAdIFW2kXeKXsuusvkguVCRGL0zcRdAYzmV6NicVAv4A/640?wx_fmt=jpeg&from=appmsg "")  
  
jwt-11  
  
顾名思义，私钥必须保密，但公钥通常是共享的，以便任何人都可以验证服务器颁发的令牌的签名。  
#### 算法混淆漏洞是如何产生的？   
  
算法混淆漏洞通常是由于 JWT 库的实现存在缺陷而引起的。尽管实际验证过程因所用算法而异，但许多库都提供了一种与算法无关的签名验证方法。这些方法依赖于alg  
令牌标头中的参数来确定应执行的验证类型。  
  
以下伪代码展示了此通用verify()  
方法在 JWT 库中的声明的简化示例：  
```
function verify(token, secretOrPublicKey){    algorithm = token.getAlgHeader();    if(algorithm == "RS256"){        // Use the provided key as an RSA public key    } else if (algorithm == "HS256"){        // Use the provided key as an HMAC secret key    }} 
```  
  
当随后使用此方法的网站开发人员认为它将专门处理使用 RS256 等非对称算法签名的 JWT 时，就会出现问题。由于这个有缺陷的假设，他们可能总是将一个固定的公钥传递给该方法，如下所示：  
```
publicKey = <public-key-of-server>;token = request.getCookie("session");verify(token, publicKey);
```  
  
在这种情况下，如果服务器收到使用对称算法（如 HS256）签名的令牌，则库的通用verify()  
方法会将公钥视为 HMAC 密钥。这意味着攻击者可以使用 HS256 和公钥对令牌进行签名，服务器将使用相同的公钥来验证签名。  
>   
> 您用于签署令牌的公钥必须与服务器上存储的公钥完全相同。这包括使用相同的格式（例如 X.509 PEM）并保留任何非打印字符（例如换行符）。实际上，您可能需要尝试不同的格式才能使此攻击奏效。  
  
#### 执行算法混淆攻击   
  
算法混淆攻击通常涉及以下高级步骤：  
1. 获取服务器的公钥  
  
1. 将公钥转换为合适的格式  
  
1. 创建具有修改后的有效负载并将alg  
标头设置为的  
恶意 JWTHS256  
。  
  
1. 使用 HS256 对令牌进行签名  
，并使用公钥作为秘密。  
  
##### 步骤 1 - 获取服务器的公钥  
  
例如，服务器有时会通过映射到/jwks.json  
或/.well-known/jwks.json  
的标准端点将其公钥公开为 JSON Web Key (JWK) 对象。这些可能存储在名为keys  
的 JWK 数组中。这称为 JWK 集。  
```
{    "keys": [        {            "kty": "RSA",            "e": "AQAB",            "kid": "75d0ef47-af89-47a9-9061-7c02a610d5ab",            "n": "o-yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw-fhvsWQ"        },        {            "kty": "RSA",            "e": "AQAB",            "kid": "d8fDFo-fS9-faS14a9-ASf99sa-7c1Ad5abA",            "n": "fc3f-yy1wpYmffgXBxhAUJzHql79gNNQ_cb33HocCuJolwDqmk6GPM4Y_qTVX67WhsN3JvaFYw-dfg6DH-asAScw"        }    ]}
```  
  
即使密钥未公开，您也可以  
从一对现有的 JWT 中提取它  
。  
##### 第 2 步 - 将公钥转换为合适的格式  
  
尽管服务器可能以 JWK 格式公开其公钥，但在验证令牌的签名时，它将使用其本地文件系统或数据库中的密钥副本。这可能以不同的格式存储。  
  
为了使攻击成功，您用于签署 JWT 的密钥版本必须与服务器的本地副本相同。除了格式相同之外，每个字节都必须匹配，包括任何非打印字符。  
  
为了便于说明，我们假设需要 X.509 PEM 格式的密钥。您可以使用Burp 中的  
JWT Editor  
扩展将 JWK 转换为 PEM，如下所示：  
1. 加载扩展后，在 Burp 的主选项卡栏中，转到**JWT 编辑器键**  
选项卡。  
  
1. 单击**“新建 RSA**  
密钥”。在对话框中，粘贴您之前获得的 JWK。  
  
1. 选择**PEM**  
单选按钮并复制生成的 PEM 密钥。  
  
1. 转到**解码器**  
选项卡并对 PEM 进行 Base64 编码。  
  
1. 返回**JWT 编辑器密钥**  
选项卡并单击**新建对称密钥**  
。  
  
1. 在对话框中，单击**“生成”**  
以生成 JWK 格式的新密钥。  
  
1. k  
使用您刚刚复制的 Base64 编码的 PEM 密钥 替换参数的生成值。  
  
1. 保存密钥。  
  
##### 步骤 3 - 修改你的 JWT  
  
获得合适格式的公钥后，您可以随意  
修改 JWT  
。只需确保alg  
标头设置为HS256  
。  
##### 步骤 4 - 使用公钥对 JWT 进行签名  
  
使用 HS256 算法对令牌进行签名，  
并使用 RSA 公钥作为秘密。  
#### Deriving public keys from existing tokens ( 从现有的 JWT（JSON Web Token）中提取或推导出用于验证签名的公钥 )   
  
如果公钥不易获得，您仍可以通过从一对现有 JWT 中派生密钥来测试算法混淆。使用 rsa_sign2n  
等工具，此过程相对简单。您可以在  
GitHub 存储库jwt_forgery.py  
上找到此脚本以及其他几个有用的脚本。  
```
docker run --rm -it portswigger/sig2n <token1> <token2>
```  
>   
> 您需要 Docker CLI 来运行该工具的任一版本。首次运行此命令时，它将自动从 Docker Hub 提取映像，这可能需要几分钟。  
  
  
这将使用您提供的 JWT 来计算n  
的一个或多个潜在值。不必太担心这意味着什么 - 您只需要知道其中只有一个与服务器密钥使用的n  
的值匹配。对于每个潜在值，我们的脚本都会输出：  
- 采用 X.509 和 PKCS1 格式的 Base64 编码 PEM 密钥。  
  
- 使用每个密钥签名的伪造 JWT。  
  
要识别正确的密钥，请使用 Burp Repeater 发送包含每个伪造 JWT 的请求。服务器只会接受其中一个。然后，您可以使用匹配的密钥构造算法混淆攻击。  
###  如何防止 JWT 攻击   
  
您可以采取以下高级措施来保护您自己的网站免遭我们介绍的许多攻击：  
- 使用最新的库来处理 JWT，并确保您的开发人员完全了解其工作原理以及任何安全隐患。现代库使您更难无意间不安全地实现它们，但由于相关规范固有的灵活性，这并非万无一失。  
  
- 确保对收到的任何 JWT 执行强大的签名验证，并考虑使用意外算法签名的 JWT 等边缘情况。  
  
- 强制执行标头允许主机的严格白名单jku  
。  
  
- 确保您不会通过kid  
标头参数受到路径遍历或 SQL 注入的攻击。  
  
###  JWT 处理的其他最佳实践   
  
尽管为了避免引入漏洞并非绝对必要，但我们建议在应用程序中使用 JWT 时遵循以下最佳实践：  
- 始终为您发行的任何令牌设置一个到期日期。  
  
- 尽可能避免在 URL 参数中发送令牌。  
  
- 包括aud  
（受众）声明（或类似内容）以指定令牌的预期接收者。这可以防止它在不同的网站上使用。  
  
- 启用发行服务器来撤销令牌（例如，在注销时）。  
  
###  Lab1 : JWT authentication bypass via unverified signature   
  
**( 实验室：通过未验证的签名绕过 JWT 身份验证 )**  
  
随意修改jwt的数据，因为不验证签名(那么中间人随意修改值，服务器也无法知道)  
  
抓登录的数据包，然后发送一下，会有一个Get请求，发现Cookie中有jwt的数据，**这里双击，会一段一段的选中，右边Inspector框会进行自动解码，第二段中的sub字段是用户名信息，修改成administrator**  
  
然后请求的地址改成 /admin  
发送到Repeater发送测试，发现成功  
  
![jwt-00](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3vKn9mcjzpn1QDLbSFR7fiaBDTqsTsWCV4bKxqIhSfObob6YPRTfbhPg/640?wx_fmt=png&from=appmsg "")  
  
jwt-00  
  
修改请求地址为 删除 carlos用户的接口，然后修改Jwt数据，直接发送即可  
  
![jwt-01](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3TdtgO35ygUbj7s8686a8eXpIzQtShabgd1H52KSfqzKygI8XfNBxhA/640?wx_fmt=png&from=appmsg "")  
  
jwt-01  
###  Lab2 : JWT authentication bypass via flawed signature verification   
  
把alg的值改成none，指的是空算法  
  
![jwt-02](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3gH0Jw5Dn4icYMECOWJc3GPdBBIUbp75aqKSGTSU68OP2Mu6WMCWh2xg/640?wx_fmt=png&from=appmsg "")  
  
jwt-02  
  
JWT可以不签名 -> 空签名算法：  
  
将alg的值为空，然后删掉签名部分，但是要保留.  
  
服务器隐式相信用户的输入 -> 空算法 -> 所以就要删掉签名部分(JWT的最后一段数据，同时要保留.  
)  
###  Lab3 : JWT authentication bypass via weak signing key   
  
直接通过hashcat爆破秘钥即可，字典已经给出  
  
![jwt-03](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3JjIyhoyicoGKBYEibyZxoMyTibMo5NPxYjWPED5liahSmeRoFO9SABd29A/640?wx_fmt=png&from=appmsg "")  
  
jwt-03  
  
得到密钥，去jwt.io  
伪造即可  
###  Lab4 : JWT authentication bypass via jwk header injection   
  
先去JWT Editor  
生成RSA密钥对  
  
![jwt-04](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3PS1ZFeia6BurLEk0YuHVIRGFwx992kHnLNbLrPWVplgspr9gBEWkSwQ/640?wx_fmt=png&from=appmsg "")  
  
jwt-04  
  
然后将Get的请求发送到Repeater，选择JWT那个选项  
  
![jwt-05](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3A54rRb0DpcufqaNBhMPtK55ZGSaJia9IicfbsByHuSXPauSFuw0vYaicA/640?wx_fmt=png&from=appmsg "")  
  
jwt-05  
  
选择Attack，嵌入JWT攻击  
  
嵌入的原理：根据现有的payload，生成一个签名，且将JWK嵌入到header中告诉服务器你要使用我的加密算法来验证。  
###  Lab5 : JWT authentication bypass via jku header injection   
  
1.生成RSA公钥，复制为JWK格式  
  
![jwt-06](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3dvGlQdtbBs4RSRfr2AAELpnTg3QRsgqArBApMGv6WZHH22lkJwRwrA/640?wx_fmt=png&from=appmsg "")  
  
jwt-06  
  
2.去exploit服务器，编辑Body区域，就是按照以下格式，将复制来的RSA的数据复制进来  
```
{    "keys": [{    "kty": "RSA",    "e": "AQAB",    "kid": "b7eee256-6633-423c-87da-529cb190f4e0",    "n": "*********"}    ]}
```  
  
3.回到Bp中，抓包，发到Repeater中  
  
3.1、修改kid为漏洞服务器中的kid，添加jku为漏洞服务器的地址 3.2、修改sub为administrator 3.3、底部Sign，选择刚刚生成的RSA，下面选择不要修改头部  
  
OK  
  
相当于是可接收JKU注入，远程接受秘钥（JKU Set格式）来进行检测  
>   
> JWK Set 是一个 JSON 对象，其中包含代表不同键的 JWK 数组  
  
  
同时，你的签名要符合这个的一个加密模式，所以要Sign一下  
###  Lab6 : JWT authentication bypass via kid header path traversal   
  
将kid指向一个空是最好的  
  
/dev/null -> ../../../../../../dev/null  
  
![jwt-07](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3qPLbyKfgLTlAtiaDicoyz173tGufB0VMCA9hAT0bicv1icp6djsz6YTs4g/640?wx_fmt=png&from=appmsg "")  
  
jwt-07  
  
k就是对应的key，改成AA==  
即空  
  
![jwt-08](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3CZmcLuiaAshfKTqkvIES4swtkLSZWCBVmg9iaL5iamjn7S2tb7jG3DeOg/640?wx_fmt=png&from=appmsg "")  
  
jwt-08  
  
然后就是，发送数据包到Repeater中去  
  
![jwt-09](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3a5xEkKwbD8hBrkWuYDQlqBBxLTUXznrRnt3jrbsWjggIAVa0sZeu8Q/640?wx_fmt=png&from=appmsg "")  
  
jwt-09  
###  Lab7 : JWT authentication bypass via algorithm confusion   
  
服务器使用非对称加密，会暴露出来公钥 通过暴露出来的公钥，生成一个相同格式的秘钥 修改头部alg的值为对称加密，从而任意修改值  
  
**1.获取服务器的公钥**  
  
**转到标准端点/jwks.json并观察服务器公开包含单个公钥的 JWK Set。**  
  
![jwt-12](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3DVVWX3dT2LAoRq7lbtAhwJHGic1ia3jl8VdCYCNI37Q97KOkO1fiaBu1g/640?wx_fmt=png&from=appmsg "")  
  
jwt-12  
  
**2.生成恶意签名秘钥**  
  
![jwt-13](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3AlWCFwSfTP5sL5OibPIqauhu4qBpPtSUNI8e1VSlE05QYmsazpibShtg/640?wx_fmt=png&from=appmsg "")  
  
jwt-13  
  
这里就是直接复制来上面得到的服务器公钥，格式要正确，然后就是OK  
  
复制为PEM格式，复制过来Decoder进行Base64编码( 这里不要乱添加乱删除，就是原样 )  
  
![jwt-14](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3OkdicIornALbShZeYdv1kdeusrnibhxpA7mGUE9v5yhEnfqOCBhiaNd7g/640?wx_fmt=png&from=appmsg "")  
  
jwt-14  
  
然后就是回去生成一个对称的秘钥  
  
![jwt-15](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3w9ANriaia3RgqYbzP6tfK6Pj1PtYaqGfC4AhrdBXYcI3W3tF29xmSP9Q/640?wx_fmt=png&from=appmsg "")  
  
jwt-15  
  
这里的k就是生成的base64编码  
  
**3.修改任意值**  
  
![jwt-16](https://mmbiz.qpic.cn/sz_mmbiz_png/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3JvmQ12ybia8Bre4ltq4MQCrmy770Csm3ItHuWGuapsfXJdIs4DGtiadA/640?wx_fmt=png&from=appmsg "")  
  
jwt-16  
###  Lab8 : JWT authentication bypass via algorithm confusion with no exposed key   
  
登录两次，拿到两次的token值  
```
docker run --rm -it portswigger/sig2n <token1> <token2>
```  
  
![jwt-17](https://mmbiz.qpic.cn/sz_mmbiz_jpg/7uLCX4hAYxFwlOKvfNVHJkEqbDjyjqn3EiaSJvmgicalY21XVmeaM1tKakaF7VGlWEcWQy62GQ4E1aLsBVBcjxmA/640?wx_fmt=jpeg&from=appmsg "")  
  
jwt-17  
  
一一拿去替换jwt去测试，如果成功的话，就用对应的key去生成密钥文件，如上一题相同  
  
  
