#  任意JavaScript代码执行(小核弹)   
 迪哥讲事   2024-05-24 22:50  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqPtBPTGrnNelnNrPAb5kPwAgEsb7SNlyW0P2ibkrhc6k4De9PicjuYJ4AaIwhfEOa6HAriascf94Dqg/640?wx_fmt=png&from=appmsg "")  
  
### 简介   
  
本文详细介绍了CVE-2024-4367，这是由Codean Labs发现的PDF.js中的一个漏洞。  
  
PDF.js是一个由Mozilla维护的基于JavaScript的PDF查看器。此漏洞允许攻击者在打开恶意PDF文件时执行任意JavaScript代码。由于Firefox使用PDF.js来显示PDF文件，所以所有Firefox用户（版本低于126）都受影响。此外，这个漏洞还严重影响了许多使用PDF.js进行预览功能的基于网页和Electron的应用程序。  
  
如果您是开发处理PDF文件的JavaScript/TypeScript应用程序的开发者，建议检查您是否（间接地）使用了易受攻击的PDF.js版本。有关缓解措施的详细信息，请参见本文末尾。  
### 介绍   
  
PDF.js 有两个常见的使用场景。首先，它是Firefox的内置PDF查看器。如果你使用Firefox，并且曾经下载或浏览过PDF文件，你就会看到它的运行效果。其次，它被打包成一个名为pdfjs-dist的Node模块，根据NPM的数据，每周下载量约为270万次。在这种形式下，网站可以使用它来提供嵌入式PDF预览功能。从Git托管平台到笔记应用程序，都在使用它。你现在想到的那个应用程序很可能正在使用PDF.js。  
  
PDF格式是出了名的复杂。它支持各种媒体类型、复杂的字体渲染，甚至包括基本的脚本功能，因此PDF阅读器常常成为漏洞研究者的目标。由于需要解析的大量逻辑，难免会出现一些错误，而PDF.js也不例外。不过，与众不同的是，PDF.js是用JavaScript编写的，而不是C或C++。这意味着它没有内存损坏问题的机会，但正如我们将看到的，它也带来了自己的一系列风险。  
### 字形渲染   
  
你可能会惊讶地发现，这个漏洞并不是与PDF格式的（JavaScript！）脚本功能有关。相反，它是字体渲染代码中特定部分的一个疏忽。  
  
PDF中的字体可以有几种不同的格式，其中一些比其他格式更晦涩（至少对我们来说是这样）。对于像TrueType这样的现代格式，PDF.js主要依赖于浏览器自身的字体渲染器。在其他情况下，它必须手动将字形（即字符）的描述转换为页面上的曲线。为了优化性能，每个字形都会预编译一个路径生成函数。如果支持，这是通过创建一个包含路径指令（jsBuf）的JavaScript函数对象来实现的：  
```
// If we can, compile cmds into JS for MAXIMUM SPEED...
if (this.isEvalSupported && FeatureTest.isEvalSupported) {
  const jsBuf = [];
  for (const current of cmds) {
    const args = current.args !== undefined ? current.args.join(",") : "";
    jsBuf.push("c.", current.cmd, "(", args, ");\n");
  }
  // eslint-disable-next-line no-new-func
  console.log(jsBuf.join(""));
  return (this.compiledGlyphs[character] = new Function(
    "c",
    "size",
    jsBuf.join("")
  ));
}

```  
  
从攻击者的角度来看，这真的很有趣：如果我们能以某种方式控制这些命令进入Function的主体，并插入我们自己的代码，那么在这种字形被渲染时，这段代码就会被执行。  
  
那么，让我们看看这些命令列表是如何生成的。追踪回CompiledFont类的逻辑，我们找到了compileGlyph(…)方法。这个方法用一些通用命令（保存、变换、缩放和恢复）初始化了cmds数组，然后交由compileGlyphImpl(…)方法来填充实际的渲染命令：  
```
  compileGlyph(code, glyphId) {
    if (!code || code.length === 0 || code[0] === 14) {
      return NOOP;
    }

    let fontMatrix = this.fontMatrix;
    ...

    const cmds = [
      { cmd: "save" },
      { cmd: "transform", args: fontMatrix.slice() },
      { cmd: "scale", args: ["size", "-size"] },
    ];
    this.compileGlyphImpl(code, cmds, glyphId);

    cmds.push({ cmd: "restore" });

    return cmds;
  }

```  
  
如果我们对PDF.js代码进行插桩以记录生成的Function对象，就会看到生成的代码确实包含这些命令：  
```
c.save();
c.transform(0.001,0,0,0.001,0,0);
c.scale(size,-size);
c.moveTo(0,0);
c.restore();

```  
  
此时，我们可以审查字体解析代码和字形可以生成的各种命令及参数，比如quadraticCurveTo和bezierCurveTo，但所有这些看起来都相当无害，除了控制数字之外没有什么能力。然而，更有趣的是我们之前看到的transform命令：  
```
{ cmd: "transform", args: fontMatrix.slice() },

```  
  
这个fontMatrix数组使用.slice()方法复制后，被插入到Function对象的主体中，并通过逗号连接起来。代码显然假设这是一个数值数组，但这种假设总是成立的吗？任何数组中的字符串都会被直接插入，而不会加上引号。这样一来，最好的结果是破坏JavaScript语法，最坏的结果是实现任意代码执行。那么，我们真的能控制fontMatrix的内容到这种程度吗？  
### 进入FontMatrix   
  
fontMatrix的默认值为[0.001, 0, 0, 0.001, 0, 0]，但通常由字体本身设置为一个自定义矩阵，也就是在其嵌入的元数据中。不同的字体格式有不同的设置方式。以下是Type1字体解析器的一个示例：  
```
  extractFontHeader(properties) {
    let token;
    while ((token = this.getToken()) !== null) {
      if (token !== "/") {
        continue;
      }
      token = this.getToken();
      switch (token) {
        case "FontMatrix":
          const matrix = this.readNumberArray();
          properties.fontMatrix = matrix;
          break;
        ...
      }
      ...
    }
    ...
  }

```  
  
虽然Type1字体在其头部技术上可以包含任意Postscript代码，但没有哪个理智的PDF阅读器会完全支持这一点，大多数仅尝试读取预定义的键值对及其预期类型。  
  
在这种情况下，PDF.js在遇到FontMatrix键时，只读取一个数字数组。CFF解析器（用于其他几种字体格式）在这方面也是类似的。总的来说，看起来我们确实被限制在数值范围内。  
  
然而，事实证明，这个矩阵有不止一个潜在来源。显然，还可以在字体外部指定自定义的FontMatrix值，即在PDF的元数据对象中！仔细观察PartialEvaluator.translateFont(...)方法，我们看到它从与字体相关的PDF字典中加载各种属性，其中之一就是fontMatrix：  
```
const properties = {
  type,
  name: fontName.name,
  subtype,
  file: fontFile,
  ...
  fontMatrix: dict.getArray("FontMatrix") || FONT_IDENTITY_MATRIX,
  ...
  bbox: descriptor.getArray("FontBBox") || dict.getArray("FontBBox"),
  ascent: descriptor.get("Ascent"),
  descent: descriptor.get("Descent"),
  xHeight: descriptor.get("XHeight") || 0,
  capHeight: descriptor.get("CapHeight") || 0,
  flags: descriptor.get("Flags"),
  italicAngle: descriptor.get("ItalicAngle") || 0,
  ...
};

```  
  
在PDF格式中，字体定义由几个对象组成：Font（字体）、FontDescriptor（字体描述符）和实际的FontFile（字体文件）。例如，这里用对象1、2和3表示  
```
1 0 obj
<<
  /Type /Font
  /Subtype /Type1
  /FontDescriptor 2 0 R
  /BaseFont /FooBarFont
>>
endobj

2 0 obj
<<
  /Type /FontDescriptor
  /FontName /FooBarFont
  /FontFile 3 0 R
  /ItalicAngle 0
  /Flags 4
>>
endobj

3 0 obj
<<
  /Length 100>>... (actual binary font data) ...endobj
```  
  
如果上述代码引用的字典指向Font对象，那么我们应该能够像这样定义一个自定义的FontMatrix数组：  
```
1 0 obj
<<
  /Type /Font
  /Subtype /Type1
  /FontDescriptor 2 0 R
  /BaseFont /FooBarFont
  /FontMatrix [1 2 3 4 5 6]   % <----->>endobj
```  
  
当尝试插入自定义的FontMatrix数组时，最初看起来不起作用，因为生成的Function体中的transform操作仍然使用默认矩阵。然而，这发生是因为字体文件本身覆盖了该值。  
  
幸运的是，当使用没有内部FontMatrix定义的Type1字体时，PDF指定的值具有权威性，因为fontMatrix值不会被覆盖。  
  
既然我们可以从PDF对象控制这个数组，那么我们就拥有了所需的所有灵活性，因为PDF支持的不仅仅是数值类型的原语。让我们尝试插入一个字符串类型的值，而不是一个数字（在PDF中，字符串用括号括起来表示）：  
```
/FontMatrix [1 2 3 4 5 (foobar)]

```  
  
确实，字符串值被直接插入到Function体内！  
```
c.save();
c.transform(1,2,3,4,5,foobar);
c.scale(size,-size);
c.moveTo(0,0);
c.restore();

```  
### 利用和影响   
  
插入任意JavaScript代码现在只是一个合理操作语法的问题。下面是一个经典示例，触发警报，首先关闭c.transform(…)函数，并利用末尾的括号：  
```
/FontMatrix [1 2 3 4 5 (0\); alert\('foobar')]

```  
  
当我们试图插入 JavaScript 代码时，结果与预期一致。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMqPtBPTGrnNelnNrPAb5kPwicyqQnAwOm2lN57EgdIiaVOKJQBne4icwFS3PKPUNqFOiban8Jwv92HA6w/640?wx_fmt=png&from=appmsg "")  
  
  
你可以在这里找到一个概念验证的 PDF 文件（已更新，请参见下面的受影响版本部分）。  
  
为了展示 JavaScript 运行的上下文，警报将显示 window.origin的值。有趣的是，这个值不是你在 URL 地址栏中看到的 file:// 路径（如果你已经下载了该文件）。  
  
相反，PDF.js 在resource://pdf.js 的来源下运行。  
  
这样做可以防止访问本地文件，但在其他方面略微更具特权。  
  
例如，可以通过对话框调用文件下载，甚至“下载”任意的 file:// URL。此外，打开的 PDF 文件的实际路径存储在 window.PDFViewerApplication.url 中，这使得攻击者可以监视打开 PDF 文件的人，不仅了解他们何时打开文件以及正在做什么，还可以了解文件在他们的计算机上的位置。  
  
在嵌入 PDF.js 的应用程序中，影响可能会更加严重。如果没有采取缓解措施（请参见下文），这基本上给了攻击者在包含 PDF 视图器的域上的 XSS 原语。  
  
根据应用程序的不同，这可能导致数据泄露，以受害者名义执行恶意操作，甚至完全接管账户。在Electron应用程序中，如果没有正确隔离 JavaScript 代码，这种漏洞甚至会导致本地代码执行（!）。我们发现至少有一个受欢迎的Electron应用程序存在这种情况。  
### 缓解措施   
  
对抗此漏洞的最佳缓解措施是将 PDF.js 更新至 4.2.67 版本或更高版本。大多数封装库如react-pdf 也发布了修补版本。因为一些更高级的 PDF 相关库静态地嵌入了 PDF.js，我们建议递归检查您的 node_modules文件夹，以确保没有名为 pdf.js 的文件。对于 PDF.js 的无头使用情况（例如，在服务器端从 PDF 中获取统计数据和数据），似乎不受影响，但我们没有进行彻底的测试。建议也进行更新。  
  
此外，一个简单的解决方法是将 PDF.js 设置 isEvalSupported 设置为 false。这将禁用易受攻击的代码路径。如果您有严格的内容安全策略（禁用 eval 和Function构造函数的使用），则漏洞也无法触及。  
### 受影响版本   
  
RobWu（已获得许可）的分析显示，易受攻击的代码路径自 PDF.js 的第一个版本发布以来就存在，但由于拼写错误，在 2016 年和 2017 年发布的几个版本中无法触及。重要的是要注意，在 2017 年及之前标记为未受影响的版本仍然容易受到另一个漏洞（CVE-2018-5158）的影响，这意味着它们不安全可用。  
- v4.2.67（于 2024 年 4 月 29 日发布）：未受影响（已修复）  
  
- v4.1.392（于 2024 年 4 月 11 日发布）：受影响（在此漏洞修复之前发布）  
  
- v1.10.88（于 2017 年 10 月 27 日发布）：受影响（由于拼写错误修复，重新引入了安全漏洞）  
  
- v1.9.426（于 2017 年 8 月 15 日发布）：未受影响（在下一个受影响版本发布之前的版本）  
  
- v1.5.188（于 2016 年 4 月 21 日发布）：未受影响（通过意外的拼写错误修复了安全漏洞）  
  
- v1.4.20（于 2016 年 1 月 27 日发布）：受影响（在下一个意外修复易受攻击代码的版本发布之前发布）  
  
- v0.8.1181（于 2014 年 4 月 10 日发布）：受影响（PDF.js 的第一个公开版本）  
  
Rob还更新了概念验证 PDF，以在所有受影响的版本上运行，包括 v1.4.20 及以下版本。请确保使用此最新版本来测试您的 PDF.js 实例是否受影响（考虑其他缓解措施）。原始的纯文本但更少通用的 PoC 可以在此找到。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
### 时间轴   
- 2024年4月26日 – 漏洞向 Mozilla 披露  
  
- 2024年4月29日 – PDF.js v4.2.67 发布到 NPM，修复了该问题  
  
- 2024年5月14日 – 发布了包含已修复的 PDF.js 版本的 Firefox 126、Firefox ESR 115.11 和 Thunderbird 115.11  
  
- 2024年5月20日 – 发布了这篇博文  
  
- 2024年5月22日 – 添加了详细的版本信息并更新了 PoC，由RobWu 提供  
  
### 漏洞评价   
  
漏洞POC:  
  
https://github.com/s4vvysec/CVE-2024-4367-POC  
```
git clone https://github.com/s4vvysec/CVE-2024-4367-POC.git
python3 poc.py malicious.pdf "alert\(document.domain\)"

```  
  
低于火狐12.6（最新版本）的直接可以触发，作用域和上文提到的一样,是在 resource://pdf.js 下面的所以是无法跨域读取到cookie的，但是呢，我们可以投放pdf利用读取  window.PDFViewerApplication  下面的信息来监控别人从哪里读取的pdf文件，如果用file://协议那么就会泄漏计算机的文件路径。  
  
这个漏洞最为离谱的在PC客户端的Electron程序上面有机会实现客户端命令执行，所以说组件漏洞的危害不亚于小核弹。  
  
这个漏洞对于安全研究者来说还是很有学习意义的，提供一个比较好的通用组件挖掘思路，后面可以继续深入下。  
  
Thanks for: https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/  
  
  
  
