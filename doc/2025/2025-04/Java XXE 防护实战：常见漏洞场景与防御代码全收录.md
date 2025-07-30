#  Java XXE 防护实战：常见漏洞场景与防御代码全收录   
原创 火力猫  季升安全   2025-04-18 13:50  
  
# 🛡️ Java XXE 防护示例与详解  
  
本文件涵盖常见 Java XML 解析器的 XXE 安全配置方法，适用学习和辅助判断审计目标是否存在XXE问题：  
- 💥 **默认行为**  
  
- ⚠️ **潜在风险**  
  
- ✅ **防护方式**  
  
- 👨‍💻 **防护代码**  
  
## 📘 1. DocumentBuilderFactory  
### 💥 默认行为：  
  
允许 DTD、实体引用，容易触发 XXE 注入。  
### ⚠️ 潜在风险：  
  
攻击者可构造外部实体，引发敏感信息读取、SSRF、DoS 等攻击。  
### ✅ 防护方式：  
  
通过 setFeature()  
 禁用 DTD 和实体加载。  
### 👨‍💻 防护代码：  
```
import javax.xml.parsers.DocumentBuilderFactory;import org.w3c.dom.Document;publicclassSafeDOMParser{publicstaticvoidmain(String[] args)throws Exception {        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);        Document doc = factory.newDocumentBuilder().parse(new java.io.ByteArrayInputStream("<xml></xml>".getBytes()));    }}
```  
## 📘 2. SAXParserFactory  
### 💥 默认行为：  
  
和 DOM 类似，也允许实体展开。  
### ⚠️ 潜在风险：  
  
构造 DTD 搭配实体即可引发漏洞。  
### ✅ 防护方式：  
  
通过 setFeature()  
 禁用危险功能。  
### 👨‍💻 防护代码：  
```
import javax.xml.parsers.SAXParserFactory;import org.xml.sax.helpers.DefaultHandler;publicclassSafeSAXParser{publicstaticvoidmain(String[] args)throws Exception {        SAXParserFactory factory = SAXParserFactory.newInstance();        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);        factory.newSAXParser().parse(new java.io.ByteArrayInputStream("<xml/>".getBytes()), new DefaultHandler());    }}
```  
## 📘 3. XMLReader  
### 💥 默认行为：  
  
不设置安全特性即有漏洞风险。  
### ⚠️ 潜在风险：  
  
使用不安全 XMLReader 导致的实体解析。  
### ✅ 防护方式：  
  
直接设置 SAX feature。  
### 👨‍💻 防护代码：  
```
import org.xml.sax.XMLReader;import org.xml.sax.helpers.XMLReaderFactory;import org.xml.sax.helpers.DefaultHandler;publicclassSafeXMLReader{publicstaticvoidmain(String[] args)throws Exception {        XMLReader reader = XMLReaderFactory.createXMLReader();        reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);        reader.setFeature("http://xml.org/sax/features/external-general-entities", false);        reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);        reader.setContentHandler(new DefaultHandler());        reader.parse(new org.xml.sax.InputSource(new java.io.StringReader("<xml/>")));    }}
```  
## 📘 4. XMLInputFactory（StAX）  
### 💥 默认行为：  
  
开启 DTD 和实体引用。  
### ⚠️ 潜在风险：  
  
即便没有 DTD，也可能加载实体。  
### ✅ 防护方式：  
  
通过 setProperty()  
 禁用 DTD、实体支持。  
### 👨‍💻 防护代码：  
```
import javax.xml.stream.*;publicclassSafeStAX{publicstaticvoidmain(String[] args)throws Exception {        XMLInputFactory factory = XMLInputFactory.newInstance();        factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);        factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);        XMLStreamReader reader = factory.createXMLStreamReader(new java.io.StringReader("<xml></xml>"));while (reader.hasNext()) {            reader.next();        }    }}
```  
##   
## 📘 5. SAXReader（dom4j）  
### 💥 默认行为：  
  
内部创建未配置的 XMLReader。  
### ⚠️ 潜在风险：  
  
默认使用不安全 reader，容易产生 XXE。  
### ✅ 防护方式：  
  
显式创建并配置 XMLReader，然后传入构造器。  
### 👨‍💻 防护代码：  
```
import org.dom4j.io.SAXReader;import org.xml.sax.XMLReader;import org.xml.sax.helpers.XMLReaderFactory;publicclassSafeSAXReader{publicstaticvoidmain(String[] args)throws Exception {        XMLReader xmlReader = XMLReaderFactory.createXMLReader();        xmlReader.setFeature("http://xml.org/sax/features/external-general-entities", false);        xmlReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);        xmlReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);        SAXReader reader = new SAXReader(xmlReader);        org.dom4j.Document doc = reader.read(new java.io.StringReader("<xml/>"));    }}
```  
## 📘 6. SAXBuilder（JDOM）  
### 💥 默认行为：  
  
若不指定 XMLReader，也使用不安全解析器。  
### ⚠️ 潜在风险：  
  
默认构造器调用未加固 parser。  
### ✅ 防护方式：  
  
传入经过配置的 XMLReader 实例。  
### 👨‍💻 防护代码：  
```
import org.jdom2.input.SAXBuilder;import javax.xml.parsers.SAXParserFactory;import org.xml.sax.XMLReader;publicclassSafeSAXBuilder{publicstaticvoidmain(String[] args)throws Exception {        SAXParserFactory factory = SAXParserFactory.newInstance();        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);        XMLReader xmlReader = factory.newSAXParser().getXMLReader();        SAXBuilder builder = new SAXBuilder(xmlReader);        org.jdom2.Document doc = builder.build(new java.io.StringReader("<xml/>"));    }}
```  
## 📘 7. XStream  
### 💥 默认行为（旧版）：  
  
可读取任意类型、支持外部实体。  
### ⚠️ 潜在风险：  
  
反序列化任意对象、文件读取。  
### ✅ 防护方式：  
- 使用 DomDriver  
；  
  
- 限制允许类型。  
  
### 👨‍💻 防护代码：  
```
import com.thoughtworks.xstream.XStream;import com.thoughtworks.xstream.io.xml.DomDriver;publicclassSafeXStream{publicstaticvoidmain(String[] args){        XStream xstream = new XStream(new DomDriver());        xstream.allowTypes(new Class[]{MyBean.class});        MyBean obj = new MyBean("hello");        String xml = xstream.toXML(obj);        System.out.println(xml);    }staticclassMyBean{private String name;publicMyBean(String name){ this.name = name; }    }}
```  
## 📘 8. JAXB  
### 💥 默认行为：  
  
若不指定安全 parser，底层仍可能存在 XXE。  
### ⚠️ 潜在风险：  
  
依赖默认 factory 引发漏洞。  
### ✅ 防护方式：  
  
配合 DOMFactory 设置特性后再解析。  
### 👨‍💻 防护代码：  
```
import javax.xml.parsers.DocumentBuilderFactory;import javax.xml.bind.*;import org.w3c.dom.Document;publicclassSafeJAXB{publicstaticvoidmain(String[] args)throws Exception {        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);        Document doc = dbf.newDocumentBuilder().parse(new java.io.ByteArrayInputStream("<user><name>xx</name></user>".getBytes()));        JAXBContext jc = JAXBContext.newInstance(User.class);        Unmarshaller unmarshaller = jc.createUnmarshaller();        User user = (User) unmarshaller.unmarshal(doc);        System.out.println(user.name);    }staticclassUser{public String name;    }}
```  
  
  
  
  
  
