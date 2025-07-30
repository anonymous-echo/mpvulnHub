#  [Web渗透】XSS漏洞挖掘   
Whoami  晨曦安全团队   2023-11-28 23:43  
  
# 知识储备  
## JavaScript  
  
JavaScript 是属于 HTML 和 Web 的编程语言。JavaScript 能够改变 HTML 内容。**案例：**JavaScript 能够改变 HTML 属性本例通过改变 <img> 标签的 src 属性（source）来改变一张 HTML 图像：  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div><div>4</div><div>5</div><div>6</div><div>7</div><div>8</div><div>9</div><div>10</div><div>11</div></td><td><div><code>&lt;!DOCTYPE html&gt;</code></div><div><code>&lt;html&gt;</code></div><div><code>&lt;body&gt;</code></div><div><code>&lt;h2&gt;JavaScript 能做什么？&lt;</code><code>/</code><code>h2&gt;</code></div><div><code>&lt;p&gt;JavaScript 能够改变 HTML 属性值。&lt;</code><code>/</code><code>p&gt;</code></div><div><code>&lt;p&gt;在本例中，JavaScript 改变了图像的 src 属性值。&lt;</code><code>/</code><code>p&gt;</code></div><div><code>&lt;button onclick</code><code>=</code><code>&#34;document.getElementById(&#39;myImage&#39;).src=&#39;/i/eg_bulbon.gif&#39;&#34;</code><code>&gt;开灯&lt;</code><code>/</code><code>button&gt;</code></div><div><code>&lt;img </code><code>id</code><code>=</code><code>&#34;myImage&#34;</code> <code>border</code><code>=</code><code>&#34;0&#34;</code> <code>src</code><code>=</code><code>&#34;/i/eg_bulboff.gif&#34;</code> <code>style</code><code>=</code><code>&#34;text-align:center;&#34;</code><code>&gt;</code></div><div><code>&lt;button onclick</code><code>=</code><code>&#34;document.getElementById(&#39;myImage&#39;).src=&#39;/i/eg_bulboff.gif&#39;&#34;</code><code>&gt;关灯&lt;</code><code>/</code><code>button&gt;</code></div><div><code>&lt;</code><code>/</code><code>body&gt;</code></div><div><code>&lt;</code><code>/</code><code>html&gt;</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_gif/42JicKqUklyjME7tZ0agyLw1KatOY2BVTfCw2ZOt5DVjHaQgOpj3xrv0AK9Czn0r1EY0dvE583YibIrOibAte5OXg/640?wx_fmt=gif&from=appmsg "")  
## JavaScript HTML DOM  
  
通过 HTML DOM，JavaScript 能够访问和改变 HTML 文档的所有元素。**HTML DOM（文档对象模型）**当网页被加载时，浏览器会创建页面的文档对象模型（Document Object Model）。HTML DOM 模型被结构化为对象树：对象的 HTML DOM 树 ![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTic0Nq6Qn3A03Ee4sOgoficrfdTRibSD62w3jVkCLTnpc20CUX11Slxlicg/640?wx_fmt=png&from=appmsg "")  
通过这个对象模型，JavaScript 获得创建动态 HTML 的所有力量：  
- JavaScript 能改变页面中的所有 HTML 元素  
  
- JavaScript 能改变页面中的所有 HTML 属性  
  
- JavaScript 能改变页面中的所有 CSS 样式  
  
- JavaScript 能删除已有的 HTML 元素和属性  
  
- JavaScript 能添加新的 HTML 元素和属性  
  
- JavaScript 能对页面中所有已有的 HTML 事件作出反应  
  
- JavaScript 能在页面中创建新的 HTML 事件  
  
HTML DOM 是 HTML 的标准对象模型和编程接口,它定义了：  
- 作为对象的 HTML 元素  
  
- 所有 HTML 元素的属性  
  
- 访问所有 HTML 元素的方法  
  
- 所有 HTML 元素的事件  
  
换言之：HTML DOM 是关于如何获取、更改、添加或删除 HTML 元素的标准。  
## HTML DOM Event 对象  
  
**HTML DOM Document 对象**  
<table><tbody><tr><td><div>1</div><div>2</div></td><td><div><code>每个载入浏览器的 HTML 文档都会成为 Document 对象。</code></div><div><code>Document 对象使我们可以从脚本中对 HTML 页面中的所有元素进行访问。</code></div></td></tr></tbody></table>  
**HTML DOM Element 对象**  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div></td><td><div><code>在 HTML DOM 中，Element 对象表示 HTML 元素。</code></div><div><code>Element 对象可以拥有类型为元素节点、文本节点、注释节点的子节点。</code></div><div><code>NodeList 对象表示节点列表，比如 HTML 元素的子节点集合。</code></div></td></tr></tbody></table>  
**HTML DOM Attribute 对象**  
<table><tbody><tr><td><div>1</div><div>2</div></td><td><div><code>在 HTML DOM 中，Attr 对象表示 HTML 属性。</code></div><div><code>HTML 属性始终属于 HTML 元素。</code></div></td></tr></tbody></table>  
**HTML DOM Event 对象**  
<table><tbody><tr><td><div>1</div><div>2</div></td><td><div><code>Event 对象代表事件的状态，比如事件在其中发生的元素、键盘按键的状态、鼠标的位置、鼠标按钮的状态。</code></div><div><code>事件通常与函数结合使用，函数不会在事件发生前被执行！</code></div></td></tr></tbody></table>## 其它前端知识  
  
学无止境  
# xss漏洞简介  
- 跨站脚本（Cross-Site Scripting，XSS）是一种经常出现在Web应用程序中的计算机安全漏洞，是由于Web应用程序对用户的输入过滤不足而产生的。  
  
- 攻击者利用网站漏洞把恶意的脚本代码（通常包括HTML代码和客户端Javascript脚本）注入到网页之中，当其他用户浏览这些网页时，就会执行其中的恶意代码，对受害用户可能采取Cookie资料窃取、会话劫持、钓鱼欺骗等各种攻击。  
  
- 由于和另一种网页技术——层叠样式表（Cascading Style Sheets，CSS）的缩写一样，为了防止混淆，故把原本的CSS简称为XSS。通常情况下，我们既可以把跨站脚本理解成一种Web安全漏洞，也可以理解成一种攻击手段。  
  
- XSS跨站脚本攻击本身对Web服务器没有直接危害，它借助网站进行传播，使网站的大量用户受到攻击。攻击者一般通过留言、电子邮件或其他途径向受害者发送一个精心构造的恶意URL，当受害者在Web浏览器中打开该URL的时侯，恶意脚本会在受害者的计算机上悄悄执行，其流程如图所示：![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTlibfnJibxwwtb78Kz6upibPyZib0MCInuGr0Q5yiav2WjSlUmAibP3BjnsaQ/640?wx_fmt=png&from=appmsg "")  
  
  
**未便于理解进行了分类归纳：**  
- 反射型XSS（也叫非持久型XSS）  
<table><tbody><tr><td><div>1</div></td><td><div><code>发出请求时，XSS代码出现在URL中，作为输入提交到服务端，服务端解析后响应，在响应内容中出现这段XSS代码，最后浏览器解析执行。这个过程就像一次反射，故称为反射型XSS。</code></div></td></tr></tbody></table>  
- 存储型XSS（也叫持久型XSS）  
<table><tbody><tr><td><div>1</div></td><td><div><code>存储型XSS和反射型XSS的差别仅在于：提交的XSS代码会存储在服务端（不管是数据库、内存还是文件系统等），下次请求目标页面时不用再提交XSS代码。</code></div></td></tr></tbody></table>  
- DOM XSS  
<table><tbody><tr><td><div>1</div></td><td><div><code>DOM XSS的XSS代码并不需要服务器解析响应的直接参与，触发XSS靠的就是浏览器端的DOM解析，可以认为完全是客户端的事情。</code></div></td></tr></tbody></table>  
**常见危害例举**挂马  
  
- 盗取用户Cookie  
  
- DoS（拒绝服务）客户端浏览器  
  
- 钓鱼攻击，高级钓鱼技巧  
  
- 编写针对性的XSS病毒  
  
- 删除目标文章  
  
- 恶意篡改数据、嫁祸、“借刀杀人”  
  
- 劫持用户Web行为，甚至进一步渗透内网  
  
- 蠕虫攻击  
  
- 蠕虫式挂马攻击、刷广告、刷流量、破坏网上数据......  
# 实战  
  
通过案例进行讲解  
## 利用本地存储功能  
  
在使用搜索功能时发现信息存在"驻留"现象![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTrZHx5C92AHIiaTZW2mTr18USRkkwPQAQde1UZ0YfVzh75QrhSocso4A/640?wx_fmt=png&from=appmsg "")  
  
  
- 打开浏览器调试工具分析**元素**![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTXsHDTMFHxDISGWSt2HSFwH6IyUyPA8thGNDhExuS00eibNsrb6V9Hvg/640?wx_fmt=png&from=appmsg "")  
  
  
**查看js代码** ![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTRvRdmSiafzB5SmRaTe8xlCGCr4Bl1cicevGexpcibtR5zuericv6dQUG8w/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div><div>4</div><div>5</div><div>6</div><div>7</div><div>8</div><div>9</div><div>10</div><div>11</div><div>12</div><div>13</div><div>14</div><div>15</div></td><td><div><code>$(</code><code>&#39;.search-ipt&#39;</code><code>).on(</code><code>&#39;input&#39;</code><code>,function () {</code></div><div><code>        </code><code>let val</code><code>=</code><code>localStorage.getItem(</code><code>&#39;record&#39;</code><code>)||&#39;&#39;</code></div><div><code>        </code><code>if</code> <code>(val!</code><code>=</code><code>&#39;&#39;){</code></div><div><code>            </code><code>$(</code><code>&#39;.history&#39;</code><code>).css(</code><code>&#39;display&#39;</code><code>,</code><code>&#39;block&#39;</code><code>)</code></div><div><code>            </code><code>$(</code><code>&#39;.history&#39;</code><code>).html(</code><code>&#39;&lt;a href=&#34;/?search=&#39;</code><code>+</code><code>val</code><code>+</code><code>&#39;&#34;&gt;&#39;</code><code>+</code><code>val</code><code>+</code><code>&#39;&lt;/a&gt;&#39;</code><code>)</code></div><div><code>        </code><code>}</code><code>else</code><code>{</code></div><div><code>            </code><code>$(</code><code>&#39;.history&#39;</code><code>).css(</code><code>&#39;display&#39;</code><code>,</code><code>&#39;none&#39;</code><code>)</code></div><div><code>        </code><code>}</code></div><div><code>    </code><code>})</code></div><div><code>    </code><code>$(</code><code>&#39;.search-btn&#39;</code><code>).click(function () {</code></div><div><code>        </code><code>let val </code><code>=</code> <code>$(</code><code>&#39;.search-ipt&#39;</code><code>).val()</code></div><div><code>        </code><code>localStorage.setItem(</code><code>&#39;record&#39;</code><code>,val)</code></div><div><code>        </code><code>}</code></div><div><code>    </code><code>)</code></div><div><code>发现将数据存储在localStorage</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTNfzghy9icVa0z0LZKlfAyvOGps9EXc5QtuaHe0JU8JicxYSa49ESCm6w/640?wx_fmt=png&from=appmsg "")  
- 输入js语句进行xss测试  
<table><tbody><tr><td><div>1</div></td><td><div><code>&lt;script&gt;alert(</code><code>&#34;xss测试&#34;</code><code>)&lt;</code><code>/</code><code>script&gt;</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVT6pcfISoMqX9VrxBh57Ms7ZFJ1E3IQIA6v9FlYjYrh5u1elYRg580NA/640?wx_fmt=png&from=appmsg "")  
  
- 搜索执行查看再次搜索成功调用并按js执行了所输入内容![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVT169YeMRVqj99VibNELgIvc12UOOt3Ubk1Lica3fqISFP9FhCJuSj1S3A/640?wx_fmt=png&from=appmsg "")  
  
  
## 简单闭合标签逃逸  
  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVT2SaAMYOGqNofGovHoBq6Aqz0HefNryjibsWRsaUHbByFkZKiaNgmwicIA/640?wx_fmt=png&from=appmsg "")  
  
   
  
发现输入的数据有驻留但在标签内  
- 查看js![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTiaYdWoUxeeWvmXjvzz7SFibWCYOufbYcss8OQMugmywvicKH7ZiaLZLcHQ/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div><div>4</div><div>5</div><div>6</div><div>7</div><div>8</div><div>9</div><div>10</div><div>11</div></td><td><div><code>$(</code><code>&#39;.search-ipt&#39;</code><code>).on(</code><code>&#39;input&#39;</code><code>,function () {</code></div><div><code>  </code><code>if</code> <code>($(</code><code>&#39;.search-ipt&#39;</code><code>).val()</code><code>=</code><code>=</code><code>&#39;&#39;){</code></div><div><code>      </code><code>$(</code><code>&#39;.history&#39;</code><code>).css(</code><code>&#39;display&#39;</code><code>,</code><code>&#39;none&#39;</code><code>)</code></div><div><code>  </code><code>}</code></div><div><code>  </code><code>else</code> <code>{</code></div><div><code>      </code><code>$(</code><code>&#39;.history&#39;</code><code>).css(</code><code>&#39;display&#39;</code><code>,</code><code>&#39;block&#39;</code><code>)</code></div><div><code>  </code><code>}</code></div><div><code>  </code><code>let val </code><code>=</code> <code>$(</code><code>&#39;.search-ipt&#39;</code><code>).val()</code></div><div><code>  </code><code>$(</code><code>&#39;.history&#39;</code><code>).html(</code><code>&#39;&lt;a href=&#34;/?search=&#39;</code><code>+</code><code>val</code><code>+</code><code>&#39;&#34;&gt;暂无搜索结果&lt;/a&gt;&#39;</code><code>)</code></div><div><code>})</code></div><div><code>发现取内容放在&lt;a标签内</code></div></td></tr></tbody></table>  
- 输入测试![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTuAUNIoJ1h4ib1M1y3C7moX2IQ66vXM0KeC7S3pvvC3KCrbvgaiaCRSbA/640?wx_fmt=png&from=appmsg "")  
  
  
- 输入特殊字符闭合标签闭合成功，输入内容以js代码形式执行![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTPy0r1MCMcVllsficmDe6fO1tGJVyiaXysSr5PHRcTkyibia3BwFGlmJnAg/640?wx_fmt=png&from=appmsg "")  
  
  
**分析：**输入"> 闭合了标签<a 并使之后的数据可不在标签内显示 ![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVT3w6TaNHJGyCGzaRfRzXsjSZSqdpHmiallVEzibYEfgedMgGRCFcCP50w/640?wx_fmt=png&from=appmsg "")  
  
## 添加事件进行逃逸  
  
正常测试，查看元素 ![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVT8Eg2IvbNWRmf4nqJ64Ep3EYjhV8EY39N6whP8fKsI8mTu41iaV8rC2w/640?wx_fmt=png&from=appmsg "")  
  
- 查看js![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTktYeE7koUl1AQHypfSLMalZXVsm1l33EicBaZJGCsAiclUAOV6jFnMCQ/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div><div>4</div><div>5</div><div>6</div><div>7</div><div>8</div><div>9</div><div>10</div><div>11</div><div>12</div></td><td><div><code>$(</code><code>&#39;.url-btn&#39;</code><code>).click(function () {</code></div><div><code>          </code><code>let val </code><code>=</code> <code>$(</code><code>&#39;.search-ipt&#39;</code><code>).val()</code></div><div><code>          </code><code>if</code> <code>(val </code><code>=</code><code>=</code> <code>&#39;&#39;) {</code></div><div><code>              </code><code>$(</code><code>&#39;.url-box&#39;</code><code>).css(</code><code>&#39;display&#39;</code><code>, </code><code>&#39;none&#39;</code><code>)</code></div><div><code>          </code><code>} </code><code>else</code> <code>{</code></div><div><code>              </code><code>val </code><code>=</code>  <code>val.toLocaleLowerCase().replace(</code><code>/</code><code>script</code><code>/</code><code>g,&#39;</code><code>&#39;).replace(/&lt;/g,&#39;</code><code>&#39;).replace(/&gt;/g,&#39;</code><code>&#39;)</code></div><div><code>              </code><code>$(</code><code>&#39;.url-box&#39;</code><code>).css(</code><code>&#39;display&#39;</code><code>, </code><code>&#39;block&#39;</code><code>)</code></div><div><code>              </code><code>$(</code><code>&#39;.url-box&#39;</code><code>).html(</code><code>&#39;&lt;span style=&#34;padding-left: 2px&#34;&gt;生成的链接为：&lt;a class=&#34;url&#34; href=&#34;&#39;</code><code>+</code><code>val</code><code>+</code><code>&#39;&#34;&gt;&#39;</code><code>+</code><code>val</code><code>+</code><code>&#39;&lt;/a&gt;&lt;/span&gt;&#39;</code><code>)</code></div><div><code>          </code><code>}</code></div><div><code>      </code><code>}</code></div><div><code>  </code><code>)</code></div><div><code>发现将数据存储在&lt;a标签href属性内</code></div></td></tr></tbody></table>  
- 闭合并添加事件![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTSAv9hHbUIMNMw171gkGseqoZODzicBebCSKrvibLrWHGWJGgaVzPorEQ/640?wx_fmt=png&from=appmsg "")  
分析：需闭合标签并逃逸herf属性  
<table><tbody><tr><td><div>1</div><div>2</div></td><td><div><code>&lt;a&gt; 标签的 href 属性用于指定超链接目标的 URL。</code></div><div><code>href
 属性的值可以是任何有效文档的相对或绝对 URL，包括片段标识符和 JavaScript 代码段。如果用户选择了 &lt;a&gt; 
标签中的内容，那么浏览器会尝试检索并显示 href 属性指定的 URL 所表示的文档，或者执行 JavaScript 表达式、方法和函数的列表。</code></div></td></tr></tbody></table>  
HTML DOM Event 对象  
<table><tbody><tr><td><div>1</div></td><td><div><code>Event 对象代表事件的状态，比如事件在其中发生的元素、键盘按键的状态、鼠标的位置、鼠标按钮的状态。</code></div></td></tr></tbody></table>  
事件句柄　(Event Handlers)  
<table><tbody><tr><td><div>1</div></td><td><div><code>HTML </code><code>4.0</code> <code>的新特性之一是能够使 HTML 事件触发浏览器中的行为，比如当用户点击某个 HTML 元素时启动一段 JavaScript。下面是一个属性列表，可将之插入 HTML 标签以定义事件的行为。</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTWp1R4JHCwthGT3b5IQKaVsiag8nzIlSEZ8TxIOePlGkXPTX4e3BHeDg/640?wx_fmt=png&from=appmsg "")  
事件通常与函数结合使用，函数不会在事件发生前被执行！onmouseover 事件会在鼠标指针移动到指定的对象上时发生  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div><div>4</div><div>5</div><div>6</div><div>7</div></td><td><div><code>支持该事件的 HTML 标签：</code></div><div><code>&lt;a&gt;,
 &lt;address&gt;, &lt;area&gt;, &lt;b&gt;, &lt;bdo&gt;, &lt;big&gt;, 
&lt;blockquote&gt;, &lt;body&gt;, &lt;button&gt;,</code></div><div><code>&lt;caption&gt;,
 &lt;cite&gt;, &lt;code&gt;, &lt;dd&gt;, &lt;dfn&gt;, &lt;div&gt;, 
&lt;dl&gt;, &lt;dt&gt;, &lt;em&gt;, &lt;fieldset&gt;,</code></div><div><code>&lt;form&gt;, &lt;h1&gt; to &lt;h6&gt;, &lt;hr&gt;, &lt;i&gt;, &lt;img&gt;, &lt;</code><code>input</code><code>&gt;, &lt;kbd&gt;, &lt;label&gt;, &lt;legend&gt;,</code></div><div><code>&lt;li&gt;, &lt;</code><code>map</code><code>&gt;, &lt;ol&gt;, &lt;p&gt;, &lt;pre&gt;, &lt;samp&gt;, &lt;select&gt;, &lt;small&gt;, &lt;span&gt;, &lt;strong&gt;,</code></div><div><code>&lt;sub&gt;, &lt;sup&gt;, &lt;table&gt;, &lt;tbody&gt;, &lt;td&gt;, &lt;textarea&gt;, &lt;tfoot&gt;, &lt;th&gt;, &lt;thead&gt;,</code></div><div><code>&lt;tr&gt;, &lt;tt&gt;, &lt;ul&gt;, &lt;var&gt;</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_gif/42JicKqUklyjME7tZ0agyLw1KatOY2BVTNMIeialibTAKEJcRtEBt1t0mXErq2Gu9bRvycBZdk5garXVb1M6E3rGg/640?wx_fmt=gif&from=appmsg "")  
  
## 打破长度  
- 输入测试  
<table><tbody><tr><td><div>1</div></td><td><div><code>&#34;&gt;&lt;script&gt;alert(</code><code>1</code><code>)&lt;</code><code>/</code><code>script&gt;</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTb5wXE160LLCqujq6xQnswzhs4vUhwGFVU2m6jqJP698ZVjkt0OMLBQ/640?wx_fmt=png&from=appmsg "")  
测试发现输入内容被过滤换测试代码  
<table><tbody><tr><td><div>1</div></td><td><div><code>&#34; onclick=&#34;</code><code>alert(</code><code>1</code><code>)</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTcfm4r6DLLd97nIpjysXhxhFqFvk0ArPicyBAe3LaI6cw4iaf26AjcEGA/640?wx_fmt=png&from=appmsg "")  
未过滤但未成功闭合  
  
- 查看代码![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTrUqXq7pkia8VSB5fLTaB2jdgx2C8k5NbzTmCZicicJXXqatjplCwwjKgA/640?wx_fmt=png&from=appmsg "")  
事件没有完全闭合后面(多了:content）*"闭合测试![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTEwDQFlrBrsOzeUCciaTnrrovLPntkSuvLVbZl13bp6dy9Qr4wepvySA/640?wx_fmt=png&from=appmsg "")  
  
  
- 深入测试![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTObXicFv7VOO7MouVe4MNC979ydyIvDk2Vc5qwdlCsic4dUoxqJpiay9OQ/640?wx_fmt=png&from=appmsg "")  
发现对代码输入的长度进行了限制  
  
- 分析前端代码![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTz1ibEGEgVfABKenqwMOAwNww3G9qSbtUYVm4yysY71o5YMbViadEuqhg/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div><div>4</div></td><td><div><code>let query </code><code>=</code> <code>getParam(</code><code>&#39;query&#39;</code><code>)||&#39;&#39;</code></div><div><code>if</code> <code>(query){</code></div><div><code>query</code><code>=</code><code>query.replace(</code><code>/</code><code>&lt;|&gt;|script</code><code>/</code><code>g,&#39;&#39;).substring(</code><code>0</code><code>, </code><code>33</code><code>)</code></div><div><code>看到使用了query参数，其值为getParam(</code><code>&#39;query&#39;</code><code>)</code></div></td></tr></tbody></table>  
- getparam()函数分析![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTE9uSPibcO4QcBEmy9QVDIxiaEOfh9BcgIHFiaqyuktjeib9mEtobIBIE2A/640?wx_fmt=png&from=appmsg "")  
  
<table><tbody><tr><td><div>1</div><div>2</div><div>3</div><div>4</div><div>5</div><div>6</div></td><td><div><code>function getParam(name) {</code></div><div><code>if</code> <code>(location.search!</code><code>=</code><code>&#39;&#39;){</code></div><div><code>let param </code><code>=</code> <code>new URLSearchParams(location.search)</code></div><div><code>return</code> <code>decodeURI(param.get(name))</code></div><div><code>}</code></div><div><code>若链接中存在参数，则创建一个对象，值为所有参数，name对应参数名</code></div></td></tr></tbody></table>  
- 测试  
<table><tbody><tr><td><div>1</div></td><td><div><code>&#34;%20onclick=&#34;</code><code>eval</code><code>(getParam(Test))&#34;&amp;Test</code><code>=</code><code>其它代码</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTZcC2d1oGxagcCtynRCNgoicyxI2yZrxicNh0V0Eq6qeGTJUSicKSuEnqQ/640?wx_fmt=png&from=appmsg "")  
成功引用。已打破输入长度限制  
  
## 拼接绕过  
- 测试  
<table><tbody><tr><td><div>1</div></td><td><div><code>&#34;</code><code>&#34; onclonclickick=&#34;</code><code>alert(</code><code>1</code><code>)&#34;</code></div></td></tr></tbody></table>  
![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVTd7YffrWgnQNxbJ3YKmtEdmQibDLsTUFEIicQ4kDXdBJrIslP9Pzaib8cA/640?wx_fmt=png&from=appmsg "")  
被过滤，发现onclick被过滤成立空字符  
  
- 拼接  
<table><tbody><tr><td><div>1</div></td><td><div><code>&#34;</code><code>&#34; onclonclickick=&#34;</code><code>alert(</code><code>1</code><code>)&#34;</code></div></td></tr></tbody></table>  
过滤一个在加一个![](https://mmbiz.qpic.cn/mmbiz_png/42JicKqUklyjME7tZ0agyLw1KatOY2BVT089uqe4nNFld0kuibJjOicyrStQVIYTrOjCzpG63SF8Zibn7EfAyf2eibA/640?wx_fmt=png&from=appmsg "")  
测试成功  
  
  
- ```
文章来源于互联网，只做学习交流，如有侵权请联系删除！原文链接：https://www.kanxue.com/chm.htm?id=15531&pid=node1000968
```  
  
-   
