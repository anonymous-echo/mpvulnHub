#  TouchEn nxKey键盘加密应用程序出现的许多漏洞很容易使其被黑化   
luochicun  嘶吼专业版   2023-02-22 12:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
TouchEn nxKey是韩国安全软件公司Raonsecure开发的端到端加密应用程序，用于保证键盘使用时的全方位安全，目前这个应用程序主要用于韩国的金融业务，在韩国几乎所有电脑上都安装了这款软件。如果你想在韩国操作网上银行业务，就必须使用它。不过韩国人对它的安全性并不认可，TouchEn nxKey确实在设计上包含了关键日志记录功能，但它未能充分限制外界对它的访问。此外，研究人员发现其中存在的七个安全漏洞，可以让攻击者实现从简单的拒绝服务攻击到远程代码执行攻击。  
  
2005年韩国一个黑客组织通过远程访问木马从人们的银行账户中窃取了5000万韩元(当时约合5万美元)。通过这种方式，他们不仅获得了用户的登录凭证，还获得了他们安全卡上的信息。这种安全卡类似于索引TAN，这是一种第二因素认证方法，2012年在欧盟被禁止，原因是很容易被银行木马攻破。  
  
那用户的计算机是如何被这个恶意应用程序攻击的？这听起来像是在用浏览器访问恶意网站时进行的驱动程序下载，很可能是浏览器漏洞被利用了。但是也有可能是用户被诱导安装了应用程序。如今，上述攻击场景已经不那么常见了，一是网络浏览器变得更加安全，二是银行已经完全采用了双因素验证。至少在很多国家，你通常需要另一台设备来确认交易。并且在确认时可以看到交易细节，因此不会贸然确认向其他人转账的信息。  
  
韩国则在2006/2007年强制银行交易使用TouchEn Key，当你在网页中输入数据时，该应用程序声称可以保护你的敏感数据。最终，TouchEn nxKey被扩展到支持非微软浏览器的使用场景中。  
# TouchEn nxKey的实际用处  
  
TouchEn nxKey是通过加密键盘输入来预防键盘记录。  
  
依赖TouchEn nxKey的网站运行nxKey SDK，该SDK由两部分组成：一组运行在网站上的JavaScript代码和一些服务器端代码。下面是它的工作原理：  
  
1.在使用nxKey SDK的网站上输入密码字段；2.nxKey SDK的JavaScript代码会检测到它并通知你的本地nxKey应用程序；3.nxKey应用程序在Windows内核中激活它的设备驱动程序；4.设备驱动程序现在拦截所有键盘输入，键盘输入不是由系统处理，而是被发送到nxKey应用程序。5.nxKey应用程序加密键盘输入并将其发送给nxKey SDK的JavaScript代码；6.JavaScript代码将加密的数据放入隐藏的表单字段中。实际的密码字段只接收虚拟文本。7.输入完登录凭证后，点击“登录”；8.加密的键盘输入与其他数据一起发送到服务器。9.nxKey SDK的服务器端部分对其进行解密，并从中检索纯文本密码。常规登录程序接管。  
  
一个试图记录输入到这个网站的数据的键盘记录器只能看到加密的数据。它可以看到网站使用的公钥，但没有相应的私钥。所以没有办法解密，密码是安全的。  
# 网站如何与TouchEn nxKey通信？  
  
网站如何知道计算机上安装了特定的应用程序呢？它是如何与之沟通的？  
  
最初，TouchEn nxKey需要安装其浏览器扩展。该浏览器扩展使用本机消息将请求从网站转发到应用程序，并将响应发送回网页。  
  
然而，使用浏览器扩展作为中间体已不再是最先进的技术。目前的最佳方法是网站使用WebSockets API直接与应用程序通信，不再需要浏览器扩展。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXS3UlxKhLJia10oUjuIqUT7vVIsIgokASU3zKjpw9r41sXtuuhZQ1Xcg/640?wx_fmt=png "")  
  
虽然花旗银行韩国分行等一些网站专门使用新的WebSocket方法，但釜山银行等其他网站仍然运行完全依赖浏览器扩展的旧代码。  
  
这不仅仅意味着用户仍然需要安装浏览器扩展，它还解释了软件安装后仍无法识别的频繁投诉。这些用户安装的是不支持WebSocket通信的旧版本软件。没有自动更新，目前韩国一些银行仍然提供这些旧版本的下载。  
# 滥用TouchEn扩展攻击银行网站  
  
TouchEn浏览器扩展真的很小，它的功能是最少的。通过它的代码，我们看到了这样的评论：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXVNAHUaVmwmQKpRxmibaR5PV88HFExgxskr7Blm20rBZZbmd2ze0kaCQ/640?wx_fmt=png "")  
  
目前，危险的eval()调用已经从浏览器扩展中被清除了。  
  
研究人员在回调机制中发现了这样一个问题，网站可以向应用程序发送一个setcallback请求来注册一些事件。当此类事件发生时，应用程序将指示扩展调用页面上已注册的回调函数。从本质上讲，页面上的任何全局函数都可以通过名称调用。  
  
恶意网页是否可以注册其他网页的回调？有两个障碍：  
  
目标网页需要有一个含有id="setcallback"的元素；  
  
回调函数被传递到特定的选项卡；  
  
第一个障碍意味着只有使用nxKey SDK的网站会受到攻击。当通过浏览器扩展进行通信时，这些扩展将创建必要的元素。通过WebSockets进行通信不会创建这个元素，这意味着使用更新nxKey SDK的网站不会受到影响。  
  
第二个障碍似乎意味着只有加载在当前选项卡中的页面才会被攻击，例如加载在框架中的页面。除非nxKey应用程序在其响应中设置了错误的tabid值。  
  
事实验证，这非常容易。虽然应用程序使用适当的JSON解析器来处理传入数据，但响应是通过调用sprintf_s()生成的，不执行转义。因此，操纵一些响应属性并向其添加引号可以注入任意JSON属性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXOWZDzQFM0ahUDPjKJ1QRuK5K1nJibFia3ej2mFDIr0ajrsF63vdkY5tg/640?wx_fmt=png "")  
  
id属性将被复制到应用程序的响应中，这意味着响应会突然获得一个名为x的新JSON属性。此漏洞允许将tabid的任何值注入到响应中。  
  
恶意页面如何知道银行选项卡的ID？它可以使用自己的标签ID (TouchEn扩展有助于暴露)，并尝试猜测其他标签ID。或者它可以简单地将此值留空，在这种情况下，扩展很有帮助：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXHQCr8fbKf2jGgtcrLXHotlZrCbpLiaPrW9boAMBWGjOssZibczxesQew/640?wx_fmt=png "")  
  
因此，如果tabid值为空，它将向当前活动的选项卡传递消息。  
  
这意味着会发生如下可能的攻击：  
  
1.在新选项卡中打开银行网站，它将成为活动选项卡；  
  
2.等待页面加载，这样id="setcallback"的元素就出现了；  
  
3.通过TouchEn扩展发送setcallback消息以设置对某个函数的回调，同时用"tabid":""和"reply":"malicious payload"覆盖JSON响应属性。  
  
第一个回调调用立即发生。因此，将在银行网站中调用回调函数，并使用来自reply属性的恶意有效负载作为参数。  
  
一个可能的回调函数可以是eval，但还有最后一个障碍：TouchEn通过JSON.stringify()将reply属性传递给回调函数。所以我们实际上得到eval("\"malicious payload\"" ")，但这没有任何作用。  
  
另一方面，也许目标页面有jQuery？  
调用$('"  
"')将产生预期的结果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXHJPWgtJONeKhB1MFRuwF4lvMMSk80XiaG0IyqPWEqCjuWmSRIiaicRbWQ/640?wx_fmt=png "")  
  
使用TouchEn nxKey的网站很可能也会使用TouchEn Transkey(一种屏幕键盘)，这依赖于jQuery。  
总之，所有韩国银行网站似乎都严重依赖jQuery，这及易产生攻击。  
  
但是update_callback (nxKey SDK的指定回调)也可以被滥用，在传递json字符串化的数据时运行任意JavaScript代码。调用update_callback('{"FaqMove":"javascript:alert(\'Hi, this is JavaScript code running on \'+document.domain)"}')将尝试重定向到javascript:链接，并运行任意代码进行攻击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmX4ApmX9orVfOag0pVv3icr7cXt4Hyz1TyOiciaoRxU0ecq1BRvddx8Mv7w/640?wx_fmt=png "")  
  
因此，这种攻击允许恶意网站破坏任何依赖TouchEn扩展的网站。韩国银行强制用户安装的“安全”应用程序都没有检测或防止这种攻击。  
# 类似TouchEn的浏览器扩展  
  
当我开始测试时，Chrome Web Store中有两个TouchEn扩展。目前这个不太受欢迎但基本上相同的扩展已经被删除。  
  
研究人员发现了三个几乎相同的扩展：INISAFE的CrossWeb EX和Smart Manager EX以及iniLINE的CrossWarpEX。CrossWeb EX是其中最受欢迎的，目前有超过400万用户。这些扩展同样会使网站受到攻击。  
  
我的第一个想法是RaonSecure和INISAFE属于同一个公司集团。但事实似乎并非如此。  
  
以下是iniLINE软件开发公司的页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXggR36bkz0cSvMuuru53AlCZkqKo8oVc0vpHQK9wicviazNq6U5Ga7wibA/640?wx_fmt=png "")  
  
Initech和RaonSecure仅仅是合作伙伴，所以看起来iniLINE是这些浏览器扩展的开发者。  
# 通过网站使用键盘记录功能  
  
现在假设有一个恶意网站。让我们假设这个网站告诉TouchEn nxKey:“你好，用户现在在密码字段，我想要他们输入的数据。”那个网站会得到所有的键盘输入吗？  
  
是的，会的！它将获取用户键入的任何内容，无论当前哪个浏览器选项卡处于活动状态，或者浏览器本身是否处于活动状态。nxKey应用程序只是遵从请求，此时不会检查它是否有意义。事实上，它甚至会向网站提供在用户访问控制提示中输入的管理员密码。  
  
但肯定会有障碍。首先，这样的网站需要一个有效的许可证。在使用任何应用程序功能之前，它需要在get_versions调用中传递许可证：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXcfbM71qQMJmibGPxfZE8aeCPRjT9NffuM84xEaoCewmZksldicNJwhRQ/640?wx_fmt=png "")  
  
此特定的许可证仅对www.example.com有效。所以只能在www.example.com网站上使用。或者被任何声称是www.example.com的网站。  
  
看到上面代码中的origin属性了吗？是的，TouchEn nxKey实际上相信，而不是查看Origin HTTP标头。因此，从一些合法使用nxKey的网站获取许可证并声称自己就是该网站是很简单的。另一个障碍是：恶意网站接收到的数据不会被加密吗？如何解密呢？应该可以使用不同的公钥，即已知私钥的公钥。那么人们只需要知道算法，然后解密数据就可以了。  
  
不过，这些都不是必要的。如果TouchEn nxKey根本没有接收到任何公钥，它释放密钥，这样该网站将接收明文键盘输入。  
  
概念验证页面：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXObEOlwWxBoXCibG7exjNydTzzAA41wP47PiaTMvFT1icKt8EJ5ibntTLpA/640?wx_fmt=png "")  
  
还有第三个障碍，这大大降低了这个漏洞的严重程度，被恶意网页拦截的键盘输入不再到达目的地。当用户开始输入密码时，肯定会感到可疑，但文本字段中却没有显示任何内容。我对nxKey应用程序的分析表明，它只能这样工作：键盘输入要么到达网页，要么到达实际目标，但不能同时实现。  
# 攻击应用程序  
  
如上所述，编写这个产品JavaScript代码的人并不精通它。但也许是因为他们所有的专家都有c++背景？我们以前已经看到过这种情况，开发人员试图尽快放弃JavaScript，将所有任务委托给c++代码。  
  
遗憾的是，这还只是猜测。与二进制代码相比，我更习惯于分析JavaScript，但应用程序本身似乎也同样充满了漏洞。事实上，它主要使用C而不是c++的典型方法，其中有很多手动内存管理。  
  
上述已经提到过sprintf_s()的使用，关于像sprintf_s()或strcpy_s()这样的函数，有一个有趣的事实，虽然它们是sprintf()或strcpy()函数的“内存安全”版本，不会溢出缓冲区，但使用起来仍然很棘手。如果没有给它们足够大的缓冲区，它们将调用无效的参数处理程序。默认情况下，这会使应用程序崩溃。  
  
nxKey应用程序的缓冲区不够大，也不会改变默认行为。因此，在许多情况下，发送过大的值会使应用程序崩溃。崩溃总比缓冲区溢出好，但崩溃的应用程序无法再执行其任务。这就会造成，用户的网上银行登录表单似乎正常工作，但它现在以明文形式接收你的密码。用户只会在提交表单时注意到某些错误，从而导致错误消息，此漏洞允许拒绝服务攻击。  
  
另一个示例是，在所有的JSON解析器中，nxKey应用程序的开发人员选择了用c编写的解析器。不仅如此，他们还从2014年1月起随机选择了一个存储库状态，并且从未更新过它。空指针解引用在2014年6月修复，现在还在。因此，向应用程序发送](一个方括号)而不是JSON数据足以使其崩溃，这是一个允许拒绝服务攻击的漏洞。  
  
上面提到的应用程序许可是base64编码的数据，应用程序需要对其进行解码。解码器函数如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmX1jiblbSLdKQ70MzXTtyQHKGLRuqPML7YHsT3icBzJRahKffyq5Ehiabkg/640?wx_fmt=png "")  
  
我不确定这个函数来自何处，它与CycloneCRYPTO库的base64解码器有明显的相似之处。但是CycloneCRYPTO将结果写入预先分配的缓冲区。因此，缓冲区分配逻辑可能是由nxKey开发人员自己添加的。  
  
这种逻辑是有缺陷的，它明确地假设input_len是4的倍数。但是对于像abcd==这样的输入，它的计算将导致分配2个字节的缓冲区，尽管实际输出是3个字节。  
  
本文的概念验证页面只是向nxKey应用程序发送随机生成的许可字符串。这足以在几秒钟内使应用程序崩溃。连接调试器显示了内存攻击的明显证据：应用程序崩溃是因为它试图使用虚假内存位置读取或写入数据。  
  
现代操作系统有一些机制，可以使像这样的缓冲区溢出更难转化为代码执行漏洞。但这些机制只有在实际使用时才有帮助。然而，nxKey开发人员在应用程序加载的两个DLL上关闭了地址空间布局随机化，在四个DLL上禁用了数据执行阻止。  
# 滥用助手应用程序  
  
到目前为止，这一切都是基于网络的攻击。但是，如果恶意软件应用程序已经将其管理到系统中，并且正在寻找扩展其权限的方法，情况又会如何呢？对于一个旨在帮助对抗此类恶意软件的应用程序，TouchEn nxKey在保持其自身功能方面表现得非常糟糕。  
  
例如，只要nxKey拦截键盘输入，CKAgentNXE.exe helper应用程序就会启动。其目的是当nxKey不想处理某个密钥时，确保它被传递到正确的目标应用程序。主应用程序使用的TKAppm.dll库中的逻辑大致如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXh5FgG2Z51z5MFPnps4tzic8XibAvuI9Zz6Uvzg9yYXUZSYnOgrT8h7jg/640?wx_fmt=png "")  
  
由于nxKey应用程序是以用户的权限运行的，所以它将在每个合理的设置中运行CKAgentNXE.exe。助手应用程序在收到命令代码2后，将调用SendInput()。  
  
研究人员注意到CKAgentNXE.exe为其IPC对象设置了一个安全描述符，以允许从完整性级别为低的进程进行访问。我还注意到，安装程序在HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Low Rights\ElevationPolicy下创建注册表项，以允许自动提升CKAgentNXE.exe。这就是它点击的位置，这都是因为Internet Explorer沙盒。  
  
因此，当TouchEn Key在Internet Explorer中作为ActiveX运行时，其完整性级别为Low。以这种方式被沙盒有效地使得无法使用SendInput()。通过允许从Internet Explorer沙箱中运行和自动提升CKAgentNXE.exe，可以绕过这个限制。一旦helper应用程序开始运行，沙盒ActiveX控件就可以连接到它并要求它执行某些操作，比如调用SendInput()。  
  
除了Internet Explorer，这种方法没有任何意义，然而TouchEn nxKey也将某些任务委托给CKAgentNXE.exe，这无疑会对安全产生影响。  
  
假设我们有一个恶意软件，运行在完整性级别低。它很可能是通过利用浏览器漏洞到达那里的，但现在它被困在了那个沙箱中。唯一能做的就是等待CKAgentNXE.exe启动（迟早会发生）并使用它来发起攻击。  
  
本文的概念验证应用程序要求CKAgentNXE.exe为它生成虚假的键盘输入：Win键，然后是C、M、D和Enter键。这导致打开一个命令行提示符，该提示符以中等完整性级别（默认级别）运行。然后，真正恶意的应用程序可以输入任意命令，在沙盒外运行代码。  
  
并不是说一个真正恶意的应用程序会以这种可见的方式做事。CKAgentNXE.exe还接受命令代码5，例如，它将把任意DLL加载到任何进程中。这是一种更好的感染系统的方法。  
  
至少这一次，一个强制性安全应用程序决定让自己变得有用，并标记为威胁：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXKu3g3fmv2Uib9pwUt13Re3V5TvAtBnV56J7ud7fejzG3fambxkk8g1Q/640?wx_fmt=png "")  
  
恶意软件开发者可能会找出触发此警告的原因并绕过它。或者他们可以启动一个web套接字连接，以确保CKAgentNXE.exe启动，而不需要像真正的银行网站那样激活AhnLab应用程序。当用户点击删除恶意应用程序时，为时已晚，攻击已经成功。  
# 直接访问驱动程序的键盘记录功能  
  
如上所述，TouchEn nxKey应用程序(它从驱动程序接收的加密键盘输入)以用户权限运行，它不是一个高级应用程序，它没有特殊权限，也就无法限制对驱动程序功能的访问。系统上的任何应用程序都可以访问这个功能。它只需要知道nxKey如何与它的驱动程序通信，但这个通信协议并不复杂。  
  
TKAppm.dll是执行驱动程序通信的库，它使用Themida进行了模糊处理，Themida背后的供应商承诺：Themida®使用SecureEngine®保护技术，当以最高优先级运行时，该技术实施了前所未有的保护技术，以保护应用程序免受高级软件破解。  
  
也许nxKey开发人员认为这将提供足够的保护，防止逆向工程。然而，在运行时连接调试器允许保存已解密的TKAppm.dll内存，并将结果加载到Ghidra中进行分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXibbj0wLbnn9LMXVwI1TfJ6Kq8ymMQE9Y4st9ZwXO9D3m0EGXU9NKNDw/640?wx_fmt=png "")  
  
此时，即使是在安全模式下启动时，应用程序拒绝工作是没有用的。  
  
无论哪种方式，我都可以编写一个小型（70行代码）应用程序，连接到驱动程序并使用它拦截系统上的所有键盘输入。它不需要提升，以用户权限运行就足够了。与网页不同的是，这个应用程序还可以确保键盘输入传递到目的地，因此用户不会注意到任何内容。创建一个键盘记录器从来没有这么容易！  
  
这个键盘记录程序很好地集成了nxKey应用程序，因此，nxKey将接收键盘输入，对其进行加密，并将加密数据发送到网站。  
  
在开发内核驱动程序时，有一点你应该知道，驱动程序崩溃会导致整个系统崩溃。这就是为什么你应该特别确保你的驱动程序代码永远不会失败。  
  
nxKey使用的驱动程序是否会失败？虽然研究人员没有仔细看它，但却意外地发现它可以。应用程序将使用DeviceIoControl()请求驱动程序提供一个指向输入缓冲区的指针。驱动程序通过调用mmmaplockedpagesspecificycache()来创建这个指针。  
  
是的，这意味着这个输入缓冲区对系统上的每个应用程序都是可见的。但这不是主要问题。如果应用程序再次请求指针会发生什么？那么，驱动程序将简单地执行另一个mmmaplockedpagesspecificycache()调用。  
  
在循环中执行此操作大约20秒后，整个虚拟地址空间被耗尽，mmmaplockedpagesspecificycache()返回NULL。驱动程序不检查返回值并崩溃，此时，操作系统自动重新启动。  
# 总结  
  
通常，当披露漏洞时，它们已经被修复了。不幸的是，截止发文，上述这些漏洞都没有得到解决。我们不知道供应商计划何时解决这些问题，也不知道他们计划如何向用户推出更新，特别是考虑到银行已经发布了至少比最新版本落后三代的版本。需要注意的是，保护程序没有自动更新功能。  
  
参考及来源：https://palant.info/2023/01/09/touchen-nxkey-the-keylogging-anti-keylogger-solution/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXtWFj1iaZib3nwqAQVRS0OvFljtKZ9icHU6rGicuPTOQbficOlj6JJfAoQXw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibTJwN9WoupMyflF4jJibwmXvwibrekpZeQxUVsW6UaMobXTR5HnqbZy3SfkT2vHD4YSTFLEDv2IdeA/640?wx_fmt=png "")  
  
  
