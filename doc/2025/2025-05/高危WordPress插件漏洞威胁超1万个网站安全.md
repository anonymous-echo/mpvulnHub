#  高危WordPress插件漏洞威胁超1万个网站安全   
 黑白之道   2025-05-20 01:59  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/3xxicXNlTXLibDAqnGBpNGbiap49l9ReBibuyFo49OUgm0Kq7Ev4HxVRJdEVWx2rGXd9icibmLNmsuGdvee8Gxk0Cyuw/640?wx_fmt=jpeg&from=appmsg "")  
## 漏洞概述  
  
热门WordPress插件Eventin近日曝出严重权限提升漏洞（CVE-2025-47539），导致超过10,000个网站面临完全被控制的风险。该漏洞允许未认证攻击者无需用户交互即可创建管理员账户，从而完全掌控受影响网站。安全研究人员强烈建议用户立即升级至4.0.27版本，该版本已包含针对此关键漏洞的修复补丁。  
## 影响范围  
  
由Themewinter开发的Eventin插件被广泛用于WordPress网站的活动管理功能。由于该插件在数千个网站中的广泛部署，使得该漏洞影响尤为严重。成功利用此漏洞可能导致网站篡改、数据窃取、恶意软件注入，或被用于更大规模的僵尸网络攻击。  
## 技术细节  
  
Patchstack研究人员发现，漏洞源于Eventin插件中处理演讲者导入功能的REST API端点存在安全缺陷。该漏洞最初由安全研究员Denver Jackson于2025年4月19日通过Patchstack零日漏洞赏金计划报告，并因此获得600美元奖励。  
  
漏洞的核心问题在于import_item_permissions_check()  
函数仅简单返回true  
而未执行任何实际权限验证：  
```
public function import_item_permissions_check($request) { return true; }
```  
  
这种实现方式允许任何未认证用户访问该端点。结合处理导入用户数据时缺乏角色验证的缺陷，攻击者可以提交包含管理员角色指定的CSV文件：  
```
$args = [    'first_name' => !empty($row['name']) ? $row['name'] : '',    // 其他用户详情...    'role' => !empty($row['role']) ? $row['role'] : '',];
```  
## 修复方案  
  
Themewinter已在2025年4月30日发布的4.0.27版本中修复该漏洞，通过实施适当的权限检查并限制用户导入期间允许的角色：  
```
public function import_item_permissions_check($request) {    return current_user_can('etn_manage_organizer') || current_user_can('etn_manage_event');}
```  
  
安全专家强烈建议使用Eventin插件的WordPress网站管理员立即升级至4.0.27或更高版本。无法立即升级的用户应考虑暂时禁用该插件，由于此漏洞无需认证即可利用，其在野利用风险极高。  
  
  
> **文章来源：freebuf**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
