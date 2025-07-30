#  一文掌握 Java XXE 漏洞原理、利用与防御姿势   
原创 火力猫  季升安全   2025-04-18 14:13  
  
# 🧨 Java XXE 漏洞审计大全  
>   
> 一看就懂、二看就能用、三看就能把审计搞定！  
  
## 🧠 一、什么是 XXE？  
  
**XXE（XML External Entity）漏洞**  
是利用 XML 的“外部实体”功能，让服务器读取本地文件或访问远程地址（如 SSRF）。常见后果：  
- 读取文件（/etc/passwd  
 等）  
  
- 内网打点（SSRF）  
  
- 内存攻击（DoS）  
  
- 数据外带（OOB 数据 exfiltration）  
  
## 🕵️‍♀️ 二、审计思路总览  
  
<table><thead><tr style="box-sizing: border-box;"><th style="box-sizing: border-box;"><span cid="n8" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">重点审计点</span></span></span></th><th style="box-sizing: border-box;"><span cid="n9" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">说明</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n11" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">是否解析 XML？</span></span></span></td><td style="box-sizing: border-box;"><span cid="n12" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">关键类如：</span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">DocumentBuilder</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">, </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">SAXParser</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">, </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">SAXReader</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">, </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">SAXBuilder</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""> 等</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n14" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">是否接收用户输入？</span></span></span></td><td style="box-sizing: border-box;"><span cid="n15" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">XML 来源是否用户可控？如从 HTTP 请求中接收</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n17" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">是否禁用了 DTD 和实体？</span></span></span></td><td style="box-sizing: border-box;"><span cid="n18" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">未配置 </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">setFeature(..., false)</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""> 就危险</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n20" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">是否使用了第三方 XML 解析框架？</span></span></span></td><td style="box-sizing: border-box;"><span cid="n21" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">如 </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">XStream</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">, </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">JAXB</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">, </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">Digester</span></code></span></span></td></tr></tbody></table>## 🧪 三、漏洞分类+示例详解  
### ① DocumentBuilderFactory（最常见）  
  
📍 **审计关注点**  
：是否使用 DocumentBuilderFactory.newInstance()  
 并缺少安全配置。  
```
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();DocumentBuilder builder = factory.newDocumentBuilder();Document doc = builder.parse(new InputSource(new StringReader(xml)));
```  
  
🛠 **漏洞利用**  
：  
```
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxeSYSTEM"file:///etc/passwd">]><root>&xxe;</root>
```  
  
🔍 **问题分析：**  
默认情况下没有禁用外部实体（例如 setFeature("...external-general-entities", false)  
），会导致解析器去访问本地文件。  
### ② SAXParserFactory  
  
📍 **审计关注点**  
：工厂是否创建了 SAXParser  
，是否缺少 feature 设置。  
```
SAXParserFactory factory = SAXParserFactory.newInstance();SAXParser parser = factory.newSAXParser();parser.parse(new InputSource(new StringReader(xml)), new DefaultHandler());
```  
  
🛠 **利用方式**  
：与上面相同，可注入恶意实体。  
  
🔍 **问题分析**  
：SAX 解析器默认也支持 DTD 和实体，攻击者可植入恶意内容。  
### ③ SAXReader（dom4j）  
  
📍 **审计关注点**  
：是否直接使用 SAXReader.read()  
，XML 是否用户可控。  
```
SAXReader reader = new SAXReader();Document doc = reader.read(new StringReader(xml));
```  
  
🛠 **利用 XML**  
：  
```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxeSYSTEM"file:///etc/shadow">]><foo>&xxe;</foo>
```  
  
🔍 **问题分析**  
：SAXReader  
 默认没有禁用外部实体功能，是 XXE 高危区。  
  
### ④ SAXBuilder（JDOM）  
  
📍 **审计关注**  
：是否使用 SAXBuilder.build()  
 方法，尤其是参数是用户输入。  
```
SAXBuilder builder = new SAXBuilder();Document doc = builder.build(new StringReader(xml));
```  
  
🛠 **利用 XML**  
：同样可读文件。  
  
🔍 **问题分析**  
：JDOM 1.x 默认启用实体支持，攻击者可用 XXE 注入。  
### ⑤ XMLReader  
  
📍 **审计关注点**  
：XMLReaderFactory.createXMLReader()  
 创建的对象是否设置安全特性？  
```
XMLReader reader = XMLReaderFactory.createXMLReader();reader.parse(new InputSource(new StringReader(xml)));
```  
  
🛠 **利用 XML**  
：一模一样的恶意 DTD。  
  
🔍 **问题分析**  
：XMLReader  
 属于 SAX 机制，同样默认支持实体，需手动禁用。  
### ⑥ Digester（Apache Commons）  
  
📍 **审计关注点**  
：调用 digester.parse()  
 时的 XML 来源是否可控？  
```
Digester digester = new Digester();Object result = digester.parse(new StringReader(xml));
```  
  
🛠 **利用方式**  
：和上面一样注入恶意实体。  
  
🔍 **问题分析**  
：Digester 使用 SAX 解析器作为底层，继承其危险特性。  
### ⑦ XMLInputFactory（StAX 解析器）  
  
📍 **审计关注**  
：是否设置了 IS_SUPPORTING_EXTERNAL_ENTITIES  
、SUPPORT_DTD  
```
XMLInputFactory factory = XMLInputFactory.newInstance();XMLStreamReader xsr = factory.createXMLStreamReader(new StringReader(xml));
```  
  
🛠 **漏洞利用（SSRF）**  
：  
```
<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxeSYSTEM"http://internal-service.local:8080/api">]><data>&xxe;</data>
```  
  
🔍 **问题分析：**  
默认情况下 IS_SUPPORTING_EXTERNAL_ENTITIES = true  
。  
### ⑧ XStream  
  
📍 **审计关注点**  
：是否使用 fromXML()  
 并允许用户提交的 XML。  
```
XStream xstream = new XStream();xstream.fromXML(xml);
```  
  
🛠 **漏洞利用**  
：  
```
<!DOCTYPE foo [<!ENTITY xxeSYSTEM"file:///etc/hosts">]><foo>&xxe;</foo>
```  
  
🔍 **问题分析**  
：XStream 本身功能强大，低版本支持实体 + 任意类反序列化，属于超级高危点。  
### ⑨ JAXB（Java 原生 XML 映射）  
  
📍 **审计关注**  
：是否直接使用 unmarshaller.unmarshal()  
，是否传入外部 XML。  
```
JAXBContext ctx = JAXBContext.newInstance(Foo.class);Unmarshaller unmarshaller = ctx.createUnmarshaller();unmarshaller.unmarshal(new StringReader(xml));
```  
  
🛠 **利用方式**  
：仍可注入 DTD。  
  
🔍 **问题分析**  
：JAXB 内部使用 DocumentBuilderFactory  
，如果未配置安全特性就有风险。  
## 📌 四、XXE 审计关键词清单  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">关键词</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">用途</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">DocumentBuilderFactory</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">DOM 解析器（最常见）</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">newDocumentBuilder()</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">创建解析器</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">parse(</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">是否使用了解析方法</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">SAXParserFactory</span></code><section><span leaf=""> / </span><code><span leaf="">newSAXParser()</span></code></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">SAX 类型解析器</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">SAXReader</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">dom4j 解析器</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">SAXBuilder</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">JDOM 框架</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">XMLInputFactory</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">StAX 解析器</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">Digester</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Apache Commons</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">XStream</span></code><section><span leaf=""> / </span><code><span leaf="">fromXML</span></code></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">第三方框架，高危点</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">Unmarshaller</span></code><section><span leaf=""> / </span><code><span leaf="">JAXBContext</span></code></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">JAXB 框架</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">setFeature</span></code></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">关键审计点，看是否禁用了 DTD 和实体</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><code><span leaf="">SUPPORT_DTD</span></code><section><span leaf=""> / </span><code><span leaf="">IS_SUPPORTING_EXTERNAL_ENTITIES</span></code></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">特别针对 StAX</span></section></td></tr></tbody></table>  
## ✅ 五、总结  
  
🧭 看代码时，重点关注3个问题：  
1. **有没有 XML 解析？**  
（关键词+代码）  
  
1. **用户能不能控制 XML 内容？**  
  
1. **有没有禁用外部实体和 DTD？**  
  
1. 上面主要类型，在代码中未发现 setFeaturesetProperty  
 的相关配置大概率就有问题  
  
1. 防护常见写法👉[Java XXE 防护实战：常见漏洞场景与防御代码全收录](https://mp.weixin.qq.com/s?__biz=MzkxNjY5MDc4Ng==&mid=2247484761&idx=1&sn=b7d7b5ce940c87fb62bf7552fe8635c5&scene=21#wechat_redirect)  
  
  
  
  
  
  
  
