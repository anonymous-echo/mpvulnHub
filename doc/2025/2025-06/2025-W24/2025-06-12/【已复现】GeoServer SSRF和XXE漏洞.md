#  【已复现】GeoServer SSRF和XXE漏洞  
 长亭安全应急响应中心   2025-06-12 11:58  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FOh11C4BDicRycsnO8OW2iauicrgUZd9Sf8AnxibANdrIGPY86Gp1CHD8ESuDPV6Kek68iaN2EMzINGmyYeWFnfibStA/640?wx_fmt=png&from=appmsg "")  
  
  
GeoServer是一个开源服务器，用于共享、处理和编辑地理空间数据。它支持多种地图和数据标准，使用户能够通过网络访问和操作地理信息系统（GIS）数据。  
  
  
2025年6月，互联网上披露GeoServer SSRF漏洞(CVE-2024-29198)漏洞和GeoServer XXE漏洞(CVE-2025-30220)，攻击者无需认证即可读取服务器上的敏感文件，最终可能导致服务器沦陷，建议受影响的客户尽快修复漏洞。  
  
  
**漏洞描述**  
  
   
Description  
   
  
  
  
**0****1**  
  
**漏洞成因**  
  
#### SSRF  
  
该系统在未设置 PROXY_BASE_URL  
 时，允许未经身份验证的用户通过 Demo 端点向服务器发起请求。这种不当配置使得攻击者能够利用 GeoServer 的功能来发送恶意请求到内部或外部网络中的其他服务器，从而导致服务器端请求伪造 (SSRF)。  
  
#### XXE  
  
GeoTools 库使用 Eclipse XSD 库来处理 XML 数据，并且未正确配置 EntityResolver  
，这导致了 XML 外部实体 (XXE) 漏洞。当 GeoServer 或 GeoNetwork 调用 GeoTools 库处理 XML 数据时，攻击者可以注入恶意的 XML 实体，进而读取本地文件或发起其他攻击。  
  
漏洞影响  
  
攻击者可读取服务器上的敏感文件（如配置文件、密钥文件等），可能导致凭据泄露，进一步利用可能导致服务器沦陷。  
  
  
**处置优先级：高**  
  
漏洞类型：SSRF/XXE  
  
**漏洞危害等级：**  
高  
  
**触发方式：**  
网络远程  
  
**权限认证要求：**  
无需权限  
  
**系统配置要求：**  
默认配置  
  
**用户交互要求：**  
无需用户交互  
  
**利用成熟度：**  
POC/EXP 未公开  
  
**修复复杂度：**  
低，  
官方提供补丁修复方案  
  
  
  
  
  
**影响版本**  
  
   
Affects  
   
  
  
  
**02**  
```
```  
  
**解决方案**  
  
   
Solution  
   
  
  
  
**03**  
  
##   
  
## SSRF临时缓解方案  
  
  
如果在没有代理的情况下直接使用 GeoServer，可以通过编辑 web.xml  
文件来阻止所有对 TestWfsPost  
的访问。在文件末尾添加以下代码块：  
  
  
<security-constraint>  
  
    <web-resource-collection>  
  
        <web-resource-name>Restrict TestWfsPost</web-resource-name>  
  
        <url-pattern>/geoserver/wfs/TestWfsPost*</url-pattern>  
  
    </web-resource-collection>  
  
    <auth-constraint>  
  
        <role-name>none</role-name>  
  
    </auth-constraint>  
  
</security-constraint>  
  
## SSRF升级修复方案GeoServer 官方已发布安全补丁，请及时更新到以下版本：GeoServer 2.24.4 或 2.25.2下载地址：https://github.com/geoserver/geoserver/releasesXXE临时缓解方案将 EntityResolver 提供给以下方法：Schemas.parse( location, locators, resolvers, uriHandlers, entityResolver);Schemas.findSchemas(Configuration configuration, EntityResolver entityResolver);XXE升级修复方案厂商已推出升级版本修复漏洞，请及时更新到以下版本：GeoServer: 2.27.1、2.26.3、2.25.7GeoTools: 33.1、32.3、31.7、28.6.1GeoNetwork: 4.4.8、4.2.13下载地址：https://github.com/geoserver/geoserver/releaseshttps://github.com/geotools/geotools/releaseshttps://github.com/geonetwork/core-geonetwork/releases漏洞复现Reproduction 04SSRFXXE产品支持Support05云图：默认支持该产品的指纹识别，同时支持该漏洞的PoC检测洞鉴：预计2025.6.13发布自定义POC支持该漏洞的PoC检测雷池：预计2025.6.13发布自定义规则，支持该漏洞利用行为的检测全悉：预计2025.6.13发布规则更新包，支持该漏洞利用行为的检测  
  
  
  
**时间线**  
  
   
Timeline  
   
  
  
  
**06**  
  
6月12日 长亭安全应急响应中心发布通告  
  
  
**长亭应急响应服务**  
  
  
  
  
全力进行产品升级  
  
及时将风险提示预案发送给客户  
  
检测业务是否受到此次漏洞影响  
  
请联系长亭应急服务团队  
  
7*24小时，守护您的安全  
  
  
第一时间找到我们：  
  
邮箱：support@chaitin.com  
  
