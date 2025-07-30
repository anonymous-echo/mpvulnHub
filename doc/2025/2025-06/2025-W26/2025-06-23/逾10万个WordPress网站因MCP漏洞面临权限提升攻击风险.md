> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323631&idx=4&sn=3fb024a33be11f2119bc8047de77f846

#  逾10万个WordPress网站因MCP漏洞面临权限提升攻击风险  
 FreeBuf   2025-06-23 11:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39Rd9FS387Ip2LW9mZ3naGsCVcErY0Q9KZcRTdZHia5fsXoL6iayn4WTIa288SchnVKZiciaGsJBHibjDg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
WordPress生态系统近日曝出高危安全漏洞，通过AI Engine插件的模型上下文协议（Model Context Protocol，MCP）实现，导致超过10万个网站面临权限提升攻击风险。  
  
  
该漏洞编号为CVE-2025-5071，CVSS评分高达8.8分，影响AI Engine插件2.8.0至2.8.3版本，攻击者仅需具备订阅者(subscriber)级别的低权限账户，即可获取目标WordPress网站的完整管理控制权。  
  
  
**Part01**  
### 漏洞技术分析  
  
  
该安全漏洞源于插件MCP功能中的授权机制缺陷，该功能允许Claude或ChatGPT等AI代理通过执行各类命令来控制和管理WordPress网站。漏洞核心在于
```
Meow_MWAI_Labs_MCP
```

  
类中的
```
can_access_mcp()
```

  
函数存在权限检查不严问题，导致未授权用户可获得强大的WordPress管理能力。  
  
  
![漏洞摘要](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39Rd9FS387Ip2LW9mZ3naGsONXtiahOXroDoJ0G8vbn5F3EibXWV3qt5HdRVEAibmqdvZdXsgmla7Yyg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Wordfence安全团队在2025年5月21日的常规威胁情报监测中发现该漏洞，并立即启动负责任的披露流程。值得注意的是，该漏洞仅对在插件设置中专门启用"开发工具"并激活MCP模块的用户构成严重威胁，这些功能默认处于关闭状态。  
  
  
**Part02**  
### 攻击影响范围  
###   
  
该漏洞的危害远超普通未授权访问，成功利用可使攻击者执行
```
wp_update_user
```

  
、
```
wp_create_user
```

  
和
```
wp_update_option
```

  
等关键命令，通过权限提升实现完全控制网站。攻击者利用插件认证框架的缺陷绕过安全控制获取管理员权限后，可上传恶意插件、修改网站内容，并在受感染网站上建立持久后门。  
  
  
Wordfence Premium、Care和Response用户已于2025年5月22日获得防护规则更新，免费版用户则在2025年6月21日获得相同保护。  
  
****  
**Part03**  
### 认证绕过技术细节  
  
  
漏洞本质在于
```
auth_via_bearer_token()
```

  
函数存在认证实现缺陷。原始漏洞代码中存在关键疏漏，当令牌值为空时，函数未能正确验证：  
  

```
public function auth_via_bearer_token( $allow, $request ) {
 if ( empty( $this->bearer_token ) ) {
  return false;
 }
 $hdr = $request->get_header( 'authorization' );
 if ( $hdr && preg_match( '/Bearer\s+(.+)/i', $hdr, $m ) &&
   hash_equals( $this->bearer_token, trim( $m[1] ) ) ) {
  return true;
 }
 return $allow;
}
```

  
### 此实现允许攻击者通过简单省略Bearer令牌来绕过认证，导致函数返回默认的$allow值（对于已登录用户默认返回true）。官方补丁通过实施严格的管理员能力检查和全面的空值验证来解决此问题。  
###   
  
**参考来源：**  
  
100,000+ WordPress Sites Exposed to Privilege Escalation Attacks via MCP AI Engine  
  
https://cybersecuritynews.com/100000-wordpress-sites-exposed/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651323514&idx=1&sn=0da8f04aecf7bbb0f3dca8f4bd1ff81f&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
