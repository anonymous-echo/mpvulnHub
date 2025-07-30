#  车联网安全 | 通过API漏洞控制全球日产LEAF车辆功能   
白帽子左一  白帽子左一   2025-05-26 04:03  
  
   
  
> 小编寄语：虽然是很老的报告，但小编认为在当下仍然具有启发意义  
  
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
  
上个月，我在挪威为   
ProgramUtvikling  
 做了一场培训，他们是我非常喜欢的 NDC 大会的主办方。我当时在讲授我惯常的 “  
Hack Yourself First  
” 研讨会，面向那些希望了解如何保护自己应用程序免受当今网络威胁的软件开发人员。在两天的培训中，我涵盖了 16 个独立的模块，从 SQL 注入、密码破解到枚举风险，几乎涉及现代开发者应关注的所有高优先级安全内容。我还讲解了如何检查、拦截和控制客户端应用（例如现代智能手机上的应用）与后端服务器服务之间的 API 请求。而就在这个环节，事情变得有趣了起来。  
  
其中一位学员受到了我们所做内容的启发，碰巧他拥有这样一辆车 ——   
全球销量最高的电动汽车  
，日产 LEAF：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icD0U3Xibp5CwKuQkE0AvY2iczxQ0kbALQn8pFEelGWrcUy1RpYPUxwNcw/640?wx_fmt=png&from=appmsg "")  
  
研讨会的这位学员最终发现，他不仅可以通过互联网连接到自己的 LEAF，并在不依赖日产官方应用设计的情况下控制相关功能，还可以控制**其他人的**  
 LEAF。后来我得知我的朋友、同时也是安全研究员的   
Scott Helme  
 也有一辆 LEAF，于是我们录制了以下视频来演示这个问题。我把它放在文章前面，是为了清楚地展示这个风险可以让人做到什么，接下来我会在文章其余部分深入讲解细节：  
  
youtube演示视频：https://www.youtube.com/embed/Nt33m7G_42Q?feature=player_embedded  
  
此视频演示你可以在多么遥远的地方控制他人汽车的功能——真的可以是地球的另一端。以下是整个发现过程的完整讲解，说明如何控制其他国家的车辆  
# 已连接的 LEAF  
  
LEAF 是一款电动汽车，在像挪威这样对远离内燃机提供大量财政激励的国家中特别受欢迎。它具备现代电动车应有的全部功能，而且由于它诞生在物联网时代，自然也配有一个配套的手机应用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icicnU0ibHWCQrdlhPmjoibks3j0uITDXHvA12uPq4GjVfiaibibibkIexOp9ibQ/640?wx_fmt=png&from=appmsg "")  
  
回到我在奥斯陆的研讨会上，好奇心驱使下，Jan在课程第一天结束后回到酒店，像我们白天操作的一样，将他的 iPhone 通过运行在 PC 上的   
Fiddler 进行代理  
（时间是1月20日）。这个设置过程只需几分钟，完成后他就可以观察移动应用是如何与在线服务通信的。随后，Jan 启动了   
NissanConnect EV 应用  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50iccvXlInib3Qicj3GdMaHbaUwEL0TvdlF7rgbKsmYJCkLGNW8Lulm313hw/640?wx_fmt=png&from=appmsg "")  
  
我使用的是公开可获取的应用截图，一方面是为了不泄露 Jan 的个人信息，另一方面是因为他的应用界面是挪威语。当应用打开时，他观察到一个类似如下的请求（在整篇文章中我都会对主机名和车辆识别码 VIN 的最后五位进行模糊处理）：  
```
GET https://[redacted].com/orchestration_1111/gdc/BatteryStatusRecordsRequest.php?RegionCode=NE&lg=no-NO&DCMID=&VIN=SJNFAAZE0U60XXXXX&tz=Europe/Paris&TimeFrom=2014-09-27T09:15:21
```  
  
它返回了如下的 JSON 响应：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icFGMspnatBMGzoHfvfwjleHIUyj4avK4runJDywPydsb1CEvic88liaCw/640?wx_fmt=png&from=appmsg "")  
  
如果你阅读一下这个响应内容，会发现它几乎不言自明：我们看到的是他那辆 LEAF 的电池状态。但吸引 Jan 注意的并不是他能获取车辆的当前状态，而是**他的手机发出的请求似乎并未包含任何有关其已认证会话的身份信息**  
。换句话说，他是在匿名访问该 API。这是一个 GET 请求，因此请求体中没有任何内容，且请求头中也没有携带诸如 Bearer Token 的信息。实际上，唯一标识他车辆身份的信息就是 VIN（车辆识别码），我已在上面的 URL 中对其做了部分模糊处理。  
  
VIN 是  
车辆识别码  
，它用于唯一标识一辆车的底盘编号。但 VIN 绝不是一种适合用于授权目的的“秘密”，这一点的重要性我稍后还会提到。  
  
表面上看，如果有人知道 Jan 的 VIN，就能获取他车辆的电池状态。虽然这并不理想，但似乎也算不上严重问题，因为这只是一次被动查询（它并不会实际  
改变  
车辆的任何内容），而且响应中也没有返回任何个人或敏感信息，除了通过 OperationDateAndTime 字段可能推测出车辆上次行驶的时间。因此，Jan 继续深入探索。  
  
他发现可以通过以下请求查看空调系统的状态：  
```
GET https://[redacted].com/orchestration_1111/gdc/RemoteACRecordsRequest.php?RegionCode=NE&lg=no-NO&DCMID=&VIN=SJNFAAZE0U60XXXXX
```  
  
随后返回了类似的状态结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icec3ZCrR6oVartlf4icz2ceMyvS7zribN3jJfLf5Dm9GlibicoExr7EUJEA/640?wx_fmt=png&from=appmsg "")  
  
这在应用程序的这个界面中有所体现：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icHSB3K0qqPVdMqyjfusuWW39AJ6BLCDcuNCDPxvbztp7zIsqdqibHB1g/640?wx_fmt=png&from=appmsg "")  
  
但这同样是被动数据 —— 空调是开启还是关闭，以及因此按钮应显示的状态。接着，他尝试打开空调，并观察到了如下请求：  
```
GET https://[redacted].com/orchestration_1111/gdc/ACRemoteRequest.php?RegionCode=NE&lg=no-NO&DCMID=&VIN=SJNFAAZE0U60XXXXX&tz=Europe/Paris
```  
  
该请求返回了如下响应：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icI1tk0fqArelJPfWFUibLw4CgYibzdGss6ibxtOFic1GTuz3AicsHZ3mdKbA/640?wx_fmt=png&from=appmsg "")  
  
这一次，返回了关于 Jan 的个人信息，即他的用户 ID，该 ID 是其真实姓名的变体。请求中传递的 VIN 也出现在了响应中，并且返回了一个 result 键。  
  
随后他关闭了空调，并观察到应用发出了如下请求：  
```
GET https://[redacted].com/orchestration_1111/gdc/ACRemoteOffRequest.php?RegionCode=NE&lg=no-NO&DCMID=&VIN=SJNFAAZE0U60XXXXX&tz=Europe/Paris
```  
  
**所有这些请求均未携带任何形式的身份验证令牌；它们都是匿名发出的。**  
 Jan 还在 Chrome 中加载了这些请求，结果同样顺利返回响应。到此为止，很明显该 API 完全没有任何访问控制，但是否能以其他车辆身份调用它尚不清楚。  
# 连接其他车辆  
  
第二天参加研讨会时，Jan 还带来了一张他通过网络搜索找到的图片：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50ic6p82o1WWrRDKToeOooW0LmAzCZwD4WOw2wsn2y0Yn8icI1FoMHArUiaw/640?wx_fmt=png&from=appmsg "")  
  
这是车辆的 VIN，显然引起了我们的好奇心（这里做了模糊处理，完整的 VIN 在网上是可以看见的）。  
  
在继续之前，我想澄清一点，这也是我在研讨会上经常强调的：当发现潜在的安全漏洞时，必须非常谨慎地考虑如何进行验证。你需要有足够的信心确认它是真正的漏洞，才能以负责任的方式报告（这也是我们最终所做的），同时还要确保不侵犯他人隐私或对他们造成任何不利影响。比如，我们不会去操作别人的车辆机械功能，比如开启空调，也不会去获取他们的个人信息，即使只是用户名。  
  
上面的 VIN 仅在最后五位数字上有所不同。我们取下这个号码并将其代入请求以获取电池状态——这是一个既不改变任何内容也不泄露任何隐私的请求——并得到了如下响应：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50ic3zunyVff57libv06XnzTx1Bz3MMKMWibKq8TOkQZbhHYnrE4h9tQ1ccQ/640?wx_fmt=png&from=appmsg "")  
  
这似乎表明响应无法被处理，但原因尚不清楚。经过反思，有可能该 VIN 并未在应用中注册。也有可能我之前分享的第一个 URL 中的某个查询字符串参数对于该 VIN 无效。例如，RegionCode 字段可能与车辆所在位置不匹配。由于无法从 API 得到明确的正面响应，我们不能断言确实存在授权缺失的问题。  
  
不过，VIN 的特点是容易被枚举。Jan 的 VIN 和在网上找到的 VIN 除了最后五位数字外完全相同，这意味着我们可以使用像   
Burp Suite  
 这样的工具轻松测试其他可能的匹配。我们通过 Burp 代理了 Chrome，然后再次发出了电池状态请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icClFQp8HjIFhOicT1C9fDPjYt5l69MqLyf1d6YRs9rMmibtXCw3W7qDsA/640?wx_fmt=png&from=appmsg "")  
  
然后我们将请求发送到 Intruder 功能，并添加了一个用于插入有效载荷的位置：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icFeWulsy0fjOrX5QQ3LkgXbB3UZmibmO676k7ct96piaiarvGBgDGficKng/640?wx_fmt=png&from=appmsg "")  
  
这就是 VIN 的最后五位数字，也是 Jan 的和网上找到的号码之间不同的部分。（注意：并非所有 LEAF 的 VIN 都仅仅是最后 5 位数字不同，  
VIN 规范  
允许范围更广，比如可能是最后 6 位。为了节省时间，我们的测试将范围限制在已知的数字区间内。）然后我们配置 Burp 使这最后 5 位数字随机化，并选择在 10,000 到 30,000 之间的整数，这个范围涵盖了 Jan 的 VIN 和网上的 VIN：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icnULuyYTuROpupKq8JOqRqOiaqdSDpiaP1f3AyERbAh7Swjib5ZB4DYv7g/640?wx_fmt=png&from=appmsg "")  
  
这使我们能够连续发出请求，每个请求仅在有效载荷列中的 VIN 不同。我们不需要测试该范围内所有 20,000 个可能的 VIN，只需不断发出请求，直到找到   
一个  
 返回另一辆车电池状态的 VIN。我们启动 Burp 开始发出请求：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icxTPIF4lediaEoO2GDFytzrkNtA66Wnku4pV9bI6gKVJOGqsqS9OW6LA/640?wx_fmt=png&from=appmsg "")  
  
上图中的请求 0 是针对 Jan 车辆的请求，返回的响应大小为 631 字节。后续带有随机 VIN 的请求   
大多数  
 返回了 288 字节的响应，如图中所示。直到我们发现了一个不同的响应：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50ic3ttF6Au5B2sF7nTnk92iagcVwibuSLeuh4ePribDDSHaoJrCanfMYHG8g/640?wx_fmt=png&from=appmsg "")  
  
**这辆车的VIN引起了我们的好奇心**  
（我做了部分模糊处理，网络上是完整可见的）。  
  
先让我澄清一件事，也是我在培训课程中反复强调的：当发现潜在安全漏洞时，必须非常谨慎地进行验证。你需要有足够的信心，确认这确实是一个合法的漏洞，然后才进行伦理报告（这也是我们最终采取的做法）。同时，你还要确保不会侵犯他人隐私或对他人造成任何负面影响。比如，我们绝不会随意操作他人车辆的机械功能，比如开启空调，也不会去获取对方的个人信息，哪怕只是用户名而已。  
  
上面那个VIN和Jan的VIN只差最后五位数字。我们取下这五位数字，放入请求中去获取电池状态——这是一个不会更改任何信息，也不会泄露隐私的请求，结果如下：  
  
这看起来表明响应无法处理，但具体原因不明。回头想想，可能是该VIN尚未在App中注册，也可能是我之前分享的URL里某个查询参数对该VIN无效，比如RegionCode字段可能与车辆实际所在地不匹配。没有得到API的肯定响应，我们也无法断言确实存在授权缺失。  
  
不过，VIN容易被枚举。Jan的VIN和网上找到的那个VIN只有最后五位不同，这意味着我们可以用类似  
Burp Suite  
的工具，轻松测试其他可能的匹配。我们通过Burp代理Chrome，再次发送电池状态请求：  
  
接着我们将请求发送到Burp的Intruder功能，添加了一个位置用来插入有效载荷：  
  
插入的是VIN最后五位数字，这正是Jan和网上VIN唯一不同的部分。（注：并非所有LEAF的VIN只在最后5位有区别，  
VIN标准  
允许范围更广，比如最后6位。为了节省时间，我们只测试了已知范围内的数字。）然后配置Burp随机生成该5位数字，在10000到30000之间选择整数，这个范围涵盖了Jan和网络上的VIN：  
  
这样我们就可以连续发送请求，每个请求的有效载荷只在VIN的最后五位数字不同。我们不需要测试这个范围内所有2万个可能的VIN，只需发送请求直到找到  
一个  
返回了另一辆车的电池状态的响应。我们启动Burp开始发送请求：  
  
上图中请求0对应Jan的车，响应大小为631字节。之后随机VIN的响应  
大多数  
为288字节，且返回如上图所示内容。直到我们发现了一个不同响应：  
  
这不是Jan的车，而是别人的LEAF。我们怀疑只需要VIN即可识别车辆的猜测被证实，显然该服务完全没有授权机制。  
  
这不仅仅是获取车辆状态的问题，还涉及到其他API能开启或关闭空调的功能。**任何人只要枚举到VIN，都可能远程控制响应车辆的实际功能。**  
 这是极其严重的安全隐患。我们在发现问题后的第二天向日产报告了此事（因为我想先让Jan给我更多信息），但截止目前——32天后——该问题依然未解决。你可以在后文看到披露时间线，期间我们进行了多次消息沟通和电话交流，直到最近收到一封来自加拿大粉丝的邮件后，我才公开披露此事……  
# 加拿大的易受攻击LEAF  
  
正巧在披露四周整点时，我正打算再次联系日产，一封标题为“weird Nissan api”的邮件从加拿大粉丝发来，内容如下：  
> 我读了你的Vtech文章，觉得你很适合了解这件事。  
  
我是日产LEAF车主，发现日产的安全性非常糟糕。  
  
他们有个App，可以远程开始充电、启停空调/加热，还能获取车辆当前状态。  
  
http://itunes.apple.com/ca/app/nissan-canada-leaf/id450031231?mt=8  
  
  
邮件继续说明：  
> 我发现整个API都没有认证，只需要VIN就能定位车辆。更离谱的是，这些操作都是通过简单的HTTP GET请求完成的。  
  
详情见（法语网站）：  
http://menu-principal-forums-aveq.1097349.n5.nabble.com/Nissan-Canada-Leaf-Carwings-td37239i20.html#a38494  
  
  
这正是Jan在奥斯陆发现的问题，且在论坛上公开讨论。通过Google翻译浏览论坛，显然用户对日产App非常不满。事实上，有帖子建议完全绕过App，直接通过API请求控制车辆功能：  
> 给技术发烧友的消息：  
  
这是开启/关闭空调和加热的URL。将你的VIN放入URL，在浏览器里运行效果很好。可以收藏这两个书签。  
> https://canada.nissanconnect.com/owners/leaf/setHvac?vin=1N4A.....5520&fan=on  
  
https://canada.nissanconnect.com/owners/leaf/setHvac?vin=1N4A.....5520&fan=off  
  
  
帖子总结了我们的结论：  
> 这个操作对我来说完全不需要认证，非常令人惊讶，也极不安全，这意味着只要知道VIN（更何况它就写在挡风玻璃上），任何人都能控制任何车辆。看起来认证机制就是通过用户资料中的VIN来进行的。  
  
  
这事发生在  
去年12月  
，也就是几个月前。注意，上面提到的URL和我们在挪威见到的API端点不同（我把其他主机名做了模糊处理，因为没看到公开讨论，甚至路径也不同）。全球汽车厂商居然如此细分App，设计挺奇怪的。虽然汽车行业确实存在地区差异，但加拿大和挪威的API实现几乎没有复用。我猜可能是由不同的本地团队开发，没有经过全球层面的严格把关。  
  
报告加拿大问题的用户说：  
> 我的猜测是，由于App质量很差，这个漏洞迟早会被发现。那些懂技术且有空闲时间的用户会去研究那些出错的东西，试图让它们为自己工作。漏洞可能早在App改版后不久就被多次发现，但要么发现者没意识到其严重性，要么像我一样不知道该怎么办。  
  
  
他说的很对——这个风险很容易被发现，因为已经有三方独立发现它了（我挪威的学生、加拿大粉丝和论坛网友）。挪威的案例已经令人担忧，加拿大的案例证明问题已经广泛公开，但我还想进一步验证，于是请来了Scott Helme的帮忙。  
# 英国的日产LEAF  
  
完全是巧合，  
Scott Helme  
（视频里出现的那位）有一辆LEAF，他又是安全专家，我在奥斯陆培训结束后去英国和他见了面。那时我们意识到他可以帮忙验证。他帮我核实了所有内容，并拿出了自己的车来测试，确认确实只需要VIN就能控制本文描述的功能。鉴于他的参与，我让他分享了对这件事的看法，他写了这么一段话：  
> 幸运的是，日产LEAF没有其他厂家车辆常见的远程解锁或远程启动功能，否则按目前发现的漏洞状况，将是场灾难。  
  
不过恶意攻击者仍然可以给LEAF车主带来很大麻烦。远程开启空调看似没问题，但长期不断激活空调会大量消耗电池电量。就像汽油车能启动发动机开空调一样，燃料会被消耗。如果你的车夜里或上班时停在车道上，开着空调超过10小时，回来时可能电量很低……甚至可能无法启动。  
  
  
视频中我们还展示了如何从车辆获取行驶历史，画面如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG58gz0V9vyCsia9b4rNX50icMwWwTAoxdtuy4WruS6ZC5LAYvZo80QYU4ZVF35wibvh6KqvdTXQuWIw/640?wx_fmt=png&from=appmsg "")  
  
这是他在2月21日两次行程的记录，当时他把儿子送到他父母家。他当天还进行了另外两次行程，一次去滑雪板，一次返回。所有这些行程都被车辆系统记录，并且如果你知道他的车辆识别码（VIN），这些记录是公开可访问的。车辆挡风玻璃上就显示着VIN，或者也可以通过枚举最后五位数字来猜测。  
  
这会泄露车辆每日的移动细节，从而带来各种隐私风险。Scott对此也有评论：  
> 另一主要担忧是车载远程信息处理系统泄露了我所有的历史驾驶数据。也就是我所有驾驶行程的细节，包括什么时候开车、开了多远，甚至驾驶效率如何。考虑到数据几乎可以追溯近两年，这很容易被用来构建我的驾驶习惯档案，甚至预测我什么时候不在家。此类数据的收集和保护必须极度尊重我的隐私。  
  
  
虽然这些信息并非直接的个人身份信息，比如住址，但一旦你拥有了某辆注册于特定国家的LEAF的VIN，要找到车主身份并不难。比如在澳大利亚，我们有像   
revscheck.com.au  
 这样的服务，只需VIN即可查询  
相当详细的数据  
。挪威则有类似的服务   
vegvesen.no  
。我怀疑，一旦知道VIN，能获得车辆和车主更多信息的途径还有很多，这就引出了更多潜在的隐私风险。  
# 解决风险及如何退出服务  
  
根本的风险很简单，我引用Scott的评论：  
> 这个API真是疯狂。不是没做身份验证或检查，而是根本没实现安全措施……  
  
它被有意设计成没有安全机制……  
  
  
显然，解决方法就是对所有API调用实现适当的授权，这对一个从头开发的应用来说是个简单的功能，但对已有的“棕地”应用就复杂多了。日产的情况更复杂，因为他们欧洲和英国用的API与加拿大的完全不同，欧洲API甚至托管在非日产所有的公司——“ZENRIN DataCom CO.,LTD.”，这意味着可能有多个不同方控制的API端点需要修复。接下来，还得更新iOS、Android等各种客户端应用，并推送给用户。等待这一切完成期间，LEAF车主的风险仍然存在。  
  
因为会有人问，我问了Scott他如何退出这个服务，他给了操作步骤：  
> 由于很容易枚举有效的VIN，这个问题令人担忧。有人一天使用加热和车内设备把我车电耗光会很麻烦，且我的全部驾驶历史被暴露也是隐私隐患。要禁用CarWings，车主必须用浏览器登录服务，手机App不能操作。登录后选择“Configuration”，那里有一个“Remove CarWings”的按钮，虽然显示为灰色，但可以点击。点击后会提示确认禁用CarWings，并要求填写原因。选择合适的理由后点击“Validate”，会收到确认消息，禁用成功，且通常会收到邮件确认。等日产修复此问题后，就可以重新启用CarWings账号，继续使用相关功能。只需登录账号，按提示操作即可。  
  
  
日产的“CarWings”是其远程信息处理服务，在英国可通过   
日产官网页面  
 访问（其他国家的网址不同）。  
# 披露时间线  
  
我曾多次尝试一个多月内促使日产修复，仅在加拿大车主发邮件和法国论坛爆出后，才通知日产我将公开发布。时间线（澳大利亚东部标准时间）：  
1. 1. **1月23日**  
：将详细情况报告给日产美国信息安全威胁情报团队，获确认收到。  
  
1. 2. **1月30日**  
：电话沟通风险详情及潜在影响，随后邮件补充说明。  
  
1. 3. **2月12日**  
：邮件询问进展并提出协助，获回复“我们正在推进解决方案”。  
  
1. 4. **2月20日**  
：转发加拿大车主提供的资料及论坛讨论链接，并通知将于“下周晚些时候”发布博客。  
  
1. 5. **2月24日**  
：博客发布，距首次披露4周零4天。  
  
  
  
   
  
获取更多精彩内容，尽在Track安全社区~：  
https://bbs.zkaq.cn  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
****  
****  
****  
  
  
