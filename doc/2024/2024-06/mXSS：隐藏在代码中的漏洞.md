#  mXSS：隐藏在代码中的漏洞   
 Ots安全   2024-06-02 12:20  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
跨站点脚本 (XSS) 是一种众所周知的漏洞类型，攻击者可以将 JavaScript 代码注入易受攻击的页面。当不知情的受害者访问该页面时，注入的代码将在受害者的会话中执行。此攻击的影响可能因应用程序而异，但不会造成业务影响，例如帐户接管(ATO)、数据泄露，甚至远程代码执行(RCE)。   
  
XSS 有多种类型，例如反射型、存储型和通用型。但近年来，XSS 的变异类型因绕过 DOMPurify、Mozilla bleach、Google Caja 等清理程序而令人生畏……影响了包括 Google 搜索在内的众多应用程序。到目前为止，我们发现许多应用程序都容易受到此类攻击。  
  
但是 mXSS 是什么？   
  
（我们还在 Insomnihack 2024 演讲中探讨了这个主题：击败 Sanitizer：为什么你应该将 mXSS 添加到你的工具箱中。）  
  
背景  
  
如果您是 Web 开发人员，您可能已经集成甚至实施了某种清理措施来保护您的应用程序免受 XSS 攻击。但人们对制作合适的 HTML 清理程序有多难知之甚少。HTML 清理程序的目标是确保用户生成的内容（例如文本输入或从外部来源获取的数据）不会带来任何安全风险或破坏网站或应用程序的预期功能。  
  
实施 HTML 清理程序的主要挑战之一在于 HTML 本身的复杂性。HTML 是一种多功能语言，具有各种元素、属性和潜在组合，这些元素、属性和组合可能会影响网页的结构和行为。准确解析和分析 HTML 代码并保留其预期功能可能是一项艰巨的任务。  
  
HTML  
  
在讨论 mXSS 之前，我们先来了解一下 HTML，它是网页的基础标记语言。了解 HTML 的结构及其工作原理至关重要，因为 mXSS（突变跨站点脚本）攻击利用了 HTML 的怪癖和复杂性。  
  
HTML 被认为是一种宽容的语言，因为它在遇到错误或意外代码时具有宽容的特性。与一些更严格的编程语言不同，即使代码编写得不完美，HTML 也会优先显示内容。这种宽容的表现如下：  
  
当呈现损坏的标记时，浏览器不会崩溃或显示错误消息，而是会尝试尽可能地解释和修复 HTML，即使其中包含轻微的语法错误或缺少元素。例如，在浏览器中打开以下标记  
<p>test将按预期执行，尽管缺少结束p标记。查看最终页面的 HTML 代码时，我们可以看到解析器修复了损坏的标记并  
p自行关闭了元素：  
<p>test</p>。  
  
它为何具有宽容度：  
- 可访问性：网络应该对所有人都开放，HTML 中的小错误不应妨碍用户查看内容。宽容度允许更广泛的用户和开发人员与网络互动。  
  
- 灵活性：HTML 经常被具有不同编码经验水平的人们使用。容忍度允许一些粗心或错误，而不会完全破坏页面的功能。  
  
- 向后兼容性：网络在不断发展，但许多现有网站都是使用较旧的 HTML 标准构建的。即使这些较旧的网站不符合最新规范，Tolerance 也能确保它们仍可在现代浏览器中显示。  
  
但是我们的 HTML 解析器如何 知道 以何种方式“修复”损坏的标记？应该  
<a><b>变成  
<a></a><b></b>还是  
<a><b></b></a>？  
  
为了回答这个问题，有一个文档齐全的HTML 规范，但不幸的是，仍然存在一些歧义，导致即使在当今的主流浏览器之间也存在不同的 HTML 解析行为。  
  
突变  
  
好的，那么 HTML 可以容忍损坏的标记，这有什么关系呢？   
  
mXSS 中的 M 代表“变异”，HTML 中的变异是由于某种原因对标记所做的任何类型的改变。  
- 当解析器修复损坏的标记（<p>test  
→ <p>test</p>）时，这就是一次变异。   
  
- 规范化属性引号（<a alt=test>  
→ <a alt=”test”>），这是一种变异。  
  
- 重新排列元素（<table><a>  
→ <a></a><table></table>），这是一个突变  
  
- 等等…  
  
mXSS 利用这种行为来绕过清理，我们将在技术细节中展示示例。  
  
HTML 解析背景  
  
将长达 1500 多页的 HTML 解析标准总结为一个章节是不现实的。但是，由于它对于深入理解 mXSS 以及有效载荷的工作原理非常重要，我们必须至少涵盖一些主要主题。为了简化操作，我们开发了一个mXSS 速查表（稍后将在本博客中介绍），将这个繁琐的标准浓缩为研究人员和开发人员更易于管理的资源。  
  
不同的内容解析类型  
  
HTML 并不是一个通用的解析环境。元素以不同的方式处理其内容，有七种不同的解析模式。我们将探索这些模式，以了解它们如何影响 mXSS 漏洞：  
- 空元素  
  
area, base, br, col, embed, hr, img, input, link, meta, source, track, wbr  
- 元素template  
  
template  
- 原始文本元素  
  
script, style, noscript, xmp, iframe, noembed, noframes  
- 可转义的原始文本元素  
  
textarea, title  
- 外来内容元素  
  
svg, math  
- 明文状态  
  
plaintext  
- 普通元素  
  
All other allowed HTML elements are normal elements.  
  
我们可以使用以下示例相当容易地展示解析类型之间的区别：  
  
1、我们的第一个输入是一个div元素，它是一个“普通元素”元素：  
  
<div><a alt="</div><img src=x onerror=alert(1)>">  
  
2、另一方面，第二个输入是使用元素的类似标记style（即“原始文本”）：  
  
<style><a alt="</style><img src=x onerror=alert(1)>">  
  
查看解析后的标记，我们可以清楚地看到解析的差异：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxck7micb3JLaguYBVDV6dKnrwxYVV7R9bqyfxyIF8V6EGe7WIoCNm3YibHg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxcksgfibmWrVXaJm3skf3Z67939Kmces57IHZyaxocxUy3KLA8Ujq4eTTw/640?wx_fmt=png&from=appmsg "")  
  
元素的内容div被渲染为 HTML，a元素就创建了。看似结束符div和img标签的东西实际上是元素的属性值a，因此被渲染为元素alt的文本a而不是 HTML 标记。在style示例中，元素的内容style被渲染为原始文本，因此没有a创建任何元素，所谓的属性现在是正常的 HTML 标记。  
  
外来内容元素  
  
HTML5 引入了在网页中集成专门内容的新方法。两个关键示例是<svg>和<math>元素。这些元素利用不同的命名空间，这意味着它们遵循与标准 HTML 不同的解析规则。了解这些不同的解析规则对于减轻与 mXSS 攻击相关的潜在安全风险至关重要。  
  
让我们看一下与之前相同的例子，但这次封装在一个svg元素内：  
```
<svg><style><a alt="</style><img src=x onerror=alert(1)>">
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckuic9MksCVibzEWV1aXt0uPM6icKOlpG12zGOwWoribK88I57rwhtcYJexA/640?wx_fmt=png&from=appmsg "")  
  
在这种情况下，我们确实看到a创建了一个元素。该style元素不遵循“原始文本”解析规则，因为它位于不同的命名空间内。当位于 SVG 或 MathML 命名空间内时，解析规则会发生变化，不再遵循 HTML 语言。  
  
使用命名空间混淆技术（例如DOMPurify 2.0.0 绕过），攻击者可以操纵清理器，以不同于浏览器最终呈现内容的方式解析内容，从而逃避对恶意元素的检测。  
  
从突变到脆弱性  
  
在涵盖各种杀毒绕过时，mXSS 术语通常被广泛使用。为了更好地理解，我们将通用术语“mXSS”分为 4 个不同的子类别  
  
解析器差异  
  
虽然解析器差异可以称为通常的清理器绕过，但有时它被称为 mXSS。无论哪种方式，攻击者都可以利用清理器算法与渲染器（例如浏览器）算法之间的解析器不匹配。由于 HTML 解析的复杂性，存在解析差异并不一定意味着一个解析器是错误的而另一个是正确的。   
  
让我们以noscript元素为例，它的解析规则是：“如果启用了脚本标志，则将标记器切换到RAWTEXT 状态。否则，将标记器保持在数据状态。”（链接）这意味着，根据 JavaScript 是禁用还是启用，元素主体的noscript呈现方式不同。逻辑上，JavaScript 不会在清理器阶段启用，但会在渲染器中启用。从定义上讲，这种行为并没有错，但可能会导致绕过，例如：  
<noscript><style></noscript><img src=x onerror=”alert(1)”>  
  
JS 已禁用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckFAOhnqEaHLgNTej7ZzJnoPFq0d9tCBPaDMMFtl0zznyUVELEUYfOaA/640?wx_fmt=png&from=appmsg "")  
  
JS 已启用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckgcRCjBfqPp2mx4ZlMTPLWyB0T2gnQzQr2LnX6duK9C5Z3ibWZr4dKJg/640?wx_fmt=png&from=appmsg "")  
  
可能会出现许多其他解析器差异，例如不同的 HTML 版本、内容类型不匹配等。  
  
解析往返  
  
解析往返是一种众所周知且有据可查的现象，即：“如果使用HTML 解析器解析此算法的输出，则可能不会返回原始树结构。不经过序列化和重新解析步骤的往返树结构也可以由HTML 解析器本身生成，尽管这种情况通常不符合要求。”  
  
这意味着根据我们解析 HTML 标记的次数，生成的 DOM 树可能会发生变化。   
  
我们先看一下官方规范中提供的例子：  
  
但首先，我们需要了解一个元素不能嵌套form另一个元素：“内容模型：流内容，但没有表单元素后代。”（如规范中所写）form  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckEck5icgGG1AOZzkBbmqzbZsIOjjKlFhcfSmaQo9NqTJZh35LAicEmVsw/640?wx_fmt=png&from=appmsg "")  
  
但是如果我们继续阅读文档，他们会form通过以下标记给出一个元素如何嵌套的示例：  
```
<form id="outer"><div></form><form id="inner"><input>

html
├── head
└── body
    └── form id="outer"
        └── div
            └── form id="inner"
                └── input
```  
  
</form>由于未关闭，因此将被忽略，并且div元素  
input将与内部元素关联  
form。现在，如果此树结构被序列化并重新解析，则  
<form id="inner">开始标记将被忽略，因此input元素将与外部元素关联  
form。  
```
<html><head></head><body><form id="outer"><div><form id="inner"><input></form></div></form></body></html>

html
├── head
└── body
    └── form id="outer"
        └── div
            └── input
```  
  
攻击者可以利用此行为在清理器和渲染器之间造成命名空间混淆，从而导致绕过，例如：  
```
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>
```  
  
感谢@SecurityMB ，此处有深入介绍。  
  
XSS处理  
  
反过滤是应用程序在将过滤器的输出发送到客户端之前干扰其输出时犯的一个关键错误，本质上就是破坏了  
过滤的工作。对标记的任何微小更改都可能对最终的 DOM 树产生重大影响，从而导致  
过滤过程被绕过。我们之前在Insomni'Hack 的一次演讲和几篇博客文章中讨论过这个问题，我们在其中发现了各种应用程序中的漏洞，包括：  
  
过滤处理的陷阱：osTicket 泄露客户数据  
  
https://www.sonarsource.com/blog/pitfalls-of-desanitization-leaking-customer-data-from-osticket/  
  
代码漏洞使 Proton Mails 面临风险  
  
https://www.sonarsource.com/blog/code-vulnerabilities-leak-emails-in-proton-mail/  
  
由于代码缺陷，Tutanota 桌面中存在远程代码执行  
  
https://www.sonarsource.com/blog/remote-code-execution-in-tutanota-desktop-due-to-code-flaw/  
  
代码漏洞使 Skiff 电子邮件面临风险  
  
https://www.sonarsource.com/blog/code-vulnerabilities-put-skiff-emails-at-risk/  
  
  
下面是一个解除净化的示例，应用程序获取净化器输出并将元素重命名svg为custom-svg，这会改变元素的命名空间，并可能在重新渲染时导致 XSS。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckBBgEMRjJRZLvlngIx6dhvTksTSD8X5CGltEk0KASbm6hYjcpZzcVnQ/640?wx_fmt=png&from=appmsg "")  
  
上下文相关  
  
HTML 解析很复杂，并且会根据上下文而有所不同。例如，解析整个文档与 Firefox 中的片段解析不同（请参阅速查表上的浏览器特定部分）。在处理浏览器中从清理到渲染的变化时，开发人员可能会错误地更改渲染数据的上下文，从而导致解析差异并最终绕过清理器。由于第三方清理器不知道结果将放在哪个上下文中，因此它们无法解决这个问题。当浏览器实现内置清理器（Sanitizer API工作）时，这个问题有望得到解决。  
  
例如，应用程序清理输入，但在将其嵌入页面时，它将其封装在 SVG 中，将上下文更改为 SVG 命名空间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckcyUnHH0ruLByYWs4lHf9mCibSUBM8JY9IaX9eBn1JbH7SQWwZWkic4Iw/640?wx_fmt=png&from=appmsg "")  
  
mXSS 案例研究  
  
虽然我们过去发布过有关 mXSS 漏洞的博客文章，例如回复 calc：危害 Mailspring 的攻击链，但我们也报道过各种清理程序绕过漏洞，例如mganss/HtmlSanitizer ( CVE-2023-44390 )、Typo3 ( CVE-2023-38500 )、OWASP/java-html-sanitizer等。   
  
但是，让我们看一个简单的案例研究，该案例是一款名为 Joplin ( CVE-2023-33726 ) 的软件，这是一款用电子编写的笔记桌面应用程序。由于电子配置不安全，Joplin 中的 JS 代码可以使用 Node 内部功能，从而使攻击者能够在机器上执行任意命令。   
  
该漏洞的根源在于 sanitizer 的解析器，它通过htmlparser2 npm 包解析不受信任的 HTML 输入。该包本身声称它们不遵循规范，并且更看重速度而不是准确性：“如果您需要严格遵守 HTML 规范，请查看parse5。”  
  
我们很快就注意到这个解析器不符合规范。通过以下输入，我们可以看到解析器忽略了不同的命名空间。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckhXvVHYQXb8pxwwH7ibazgHwCWsRu8g1VVJL2SODjpxtdicRpatT4u39g/640?wx_fmt=png&from=appmsg "")  
  
虽然清理器的解析器不会渲染img元素，但渲染器会渲染元素。这是解析器差异的一个示例，攻击者只需添加onerror事件处理程序，当受害者打开恶意笔记时，该处理程序就会执行任意代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeSHu8XGicDJF2v3TblZWxckVVzMsGatyvogPvw7Q25TgZicyU9ciceO5LwKRNiaN58I1YMVpqaqC3Vzg/640?wx_fmt=png&from=appmsg "")  
  
@maple3142也独立发现了这一特定发现  
  
减轻  
  
不幸的是，没有一个简单的缓解解决方案。我们鼓励开发人员深入了解此类错误，以便他们能够根据自己的应用程序更好地决定如何缓解此问题。   
  
在我们的研究过程中，我们发现了开发人员为了解决 mXSS 问题而采取的许多缓解方法和安全措施（也可在备忘单中找到）：  
  
净化客户端  
- 这可能是要遵循的最重要的规则。使用在客户端运行的清理程序（例如DOMPurify）可避免解析器差异风险。由于解析的复杂性以及最有可能将内容提供给不同的解析器（Firefox、Chrome 和 Safari 等），当 HTML 的解析位置与最终呈现内容的位置不同时，无法避免差异。因此，服务器端清理程序很容易失败。  
  
- 当将服务器端渲染 (SSR) 与客户端 JS 框架结合使用时，可以轻松引入isomorphic-dompurify等库。它们让客户端清理器（如DOMPurify）在 SSR 模式下“正常工作”。但为了实现这一点，它们还引入了服务器端 HTML 解析器（如jsdom ），这带来了解析器差异风险。对于使用 SSR 的 Web 应用来说，最安全的选择是禁用用户控制 HTML 的 SSR，并将清理和渲染仅推迟到客户端。  
  
不要再离开  
  
为了避免“往返 mXSS”，应用程序可以将已清理的 DOM 树直接插入文档中，而无需序列化并重新呈现内容。  
  
请注意，这种方法只有在客户端实施清理程序时才可行，并且可能会导致意外行为（例如由于未适应页面上下文而以不同的方式呈现内容）。  
  
始终对原始内容进行编码或删除   
  
由于 mXSS 的理念是想办法让恶意字符串在清理器中呈现为原始文本，但稍后解析为 HTML，因此在清理器阶段不允许/编码任何原始文本将使其无法重新呈现为 HTML。  
  
请注意，这可能会破坏某些内容，例如 CSS 代码。  
  
不支持外部内容元素  
  
不支持外部内容元素（删除 svg/math 元素及其内容而不重命名）可显著降低复杂性。  
  
请注意，这不会缓解 mXSS，但提供了预防措施。  
  
支持通过父命名空间检查来清理外部元素。   
  
解决命名空间混淆问题的一个更复杂的方法是实施父命名空间检查，并删除任何位于错误命名空间中的元素。此实施的示例可在此处找到，由@SecurityMB编写。  
  
请注意，在将输出嵌入到最终页面时，确保清理器树的上下文不会发生变化仍然很重要。例如，在 HTML 命名空间中清理 DOM 树，然后将输出嵌入到标签中svg可能会导致清理绕过。  
  
未来  
  
如此复杂的问题，没有简单的解决方案，还有光明的前景吗？   
  
答案是肯定的，幸运的是，已经提出了一些建议并采取了一些行动，以结束此类错误或至少正式解决它。  
  
当今最大的问题是，清理不受信任的 HTML 输入的责任落在了第三方开发人员身上，无论是应用程序开发人员还是清理程序开发人员。由于任务的复杂性以及他们需要处理不同的渲染器解析器（不同的用户使用不同的浏览器）并跟上不断发展的 HTML 规范的事实，这是不切实际的。解决此问题的更正确方法是让渲染器负责确保标记中没有恶意内容。例如，在浏览器中内置清理程序可以消除我们迄今为止看到的大多数（如果不是全部）绕过方法。  
  
Sanitizer API计划正是如此。它目前由 Web 平台孵化器社区小组 (WICG) 开发，旨在为开发人员提供由浏览器自己编写的集成、强大且具有上下文感知能力的清理程序（不再有解析器差异或重新解析）。更广泛的浏览器采用 Sanitizer API 可能会导致开发人员更多地使用它来进行更安全的 HTML 操作。  
  
解决这个问题的另一个努力是更新规格，例如，Chrome 现在对属性中的字符<进行编码>  
```
<svg><style><a alt="</style>">→<svg><style><a alt="&lt;/style&gt;">
```  
  
不断发展 HTML 定义的基础，以实现更安全的未来。  
  
mXSS 备忘单  
  
我们创建了mXSS 速查表，旨在为任何有兴趣在 mXSS 领域学习、研究和创新的人提供一站式服务。帮助用户在简化的列表中查看意外的 HTML 行为，而不必阅读 1500 多页的文档。我们鼓励用户做出贡献，共同推动这项工作。  
  
概括  
  
mXSS（突变跨站点脚本）是一种由 HTML 处理方式引起的安全漏洞。即使 Web 应用程序具有强大的过滤器来阻止传统的 XSS 攻击，mXSS 仍可能潜入其中。这是因为 mXSS 利用 HTML 行为中的怪癖，使清理器无法发现恶意元素。   
  
本博客深入探讨了 mXSS，提供了示例，将这个大“mXSS”名称分成几个小节，并介绍了开发人员的缓解策略。通过让您掌握这些知识，我们希望开发人员和研究人员将来能够自信地解决这个问题。  
```
mXSS: The Vulnerability Hiding in Your Code
https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
