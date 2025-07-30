#  如何使用route-detect在Web应用程序路由中扫描身份认证和授权漏洞   
Alpha_h4ck  FreeBuf   2024-03-26 18:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
  
**关于route-detect**  
  
  
  
route-detect是一款功能强大的Web应用程序路由安全扫描工具，该工具可以帮助广大研究人员在Web应用程序路由中轻松识别和检测身份认证漏洞和授权漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380icNfibmv7pgNpoia5Y69wxqe4Dp2iaIQnNic0GGxNNvgxDJ5P2WuP20SN2sFyccC56s3WE83rPLW3mw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Web应用程序HTTP路由中的身份认证（authn）和授权（authz）漏洞是目前最常见的Web安全问题，下列行业标准也足以突出证明了此类安全问题的严重性：  
  
- 2021 OWASP Top 10 #1 - 访问控制中断  
  
- 2021 OWASP Top 10 #7 - 身份验证失效  
  
- 2023 OWASP API Top 10 #1 - 对象级别授权中断  
  
- 2023 OWASP API Top 10 #2 - 身份验证失效  
  
- 2023 OWASP API Top 10 #5 - 功能级别授权中断  
  
- 2023 CWE Top 25 #11 - CWE-862: 缺少授权  
  
- 2023 CWE Top 25 #13 - CWE-287: 不正确的身份验证  
  
- 2023 CWE Top 25 #20 - CWE-306: 关键功能缺少身份验证  
  
- 2023 CWE Top 25 #24 - CWE-863: 不正确的授权  
  
**支持的Web框架**  
  
  
  
当前版本的route-detect支持下列Web框架：  
  
- Python: Django (django, django-rest-framework), Flask (flask), Sanic (sanic)  
  
- PHP: Laravel (laravel), Symfony (symfony), CakePHP (cakephp)  
  
- Ruby: Rails* (rails), Grape (grape)  
  
- Java: JAX-RS (jax-rs), Spring (spring)  
  
- Go: Gorilla (gorilla), Gin (gin), Chi (chi)  
  
- JavaScript/TypeScript: Express (express), React (react), Angular (angular)  
  
**工具安装**  
  
  
  
由于该工具使用Python开发，因此我们首先需要在本地设备上安装并配置好Python环境。  
  
  
接下来，广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/mschwager/route-detect.git
```  
  
  
或者直接使用pip工具安装最新版本的route-detect：  
```
$ python -m pip install --upgrade route-detect
```  
  
  
  
安装完成后，我们可以使用下列命令检测route-detect是否安装成功：  
```
$ echo 'print(1 == 1)' | semgrep --config $(routes which test-route-detect) -

Scanning 1 file.

 

Findings:

 

  /tmp/stdin

     routes.rules.test-route-detect

        Found '1 == 1', your route-detect installation is working correctly

 

          1┆ print(1 == 1)

 

 

Ran 1 rule on 1 file: 1 finding.
```  
  
  
**工具使用**  
  
  
  
route-detect提供了routes命令并使用  
semgrep  
来搜索路由信息。  
  
  
使用which子命令可以将semgrep指向正确的Web应用程序规则：  
```
$ semgrep --config $(routes which django) path/to/django/code
```  
  
  
  
使用viz子命令可以在浏览器中可视化查看路由信息：  
```
$ semgrep --json --config $(routes which django) --output routes.json path/to/django/code

$ routes viz --browser routes.json
```  
  
  
  
如果你不确定目标Web应用程序所使用的框架，可以使用all ID检索和查看：  
```
$ semgrep --json --config $(routes which all) --output routes.json path/to/code
```  
  
  
  
如果你有自己自定义的authn或authz逻辑，可以拷贝route-detect的规则：  
```
$ cp $(routes which django) my-django.yml
```  
  
  
  
我们还可以根据需求修改并运行规则：  
```
$ semgrep --json --config my-django.yml --output routes.json path/to/django/code

$ routes viz --browser routes.json
```  
  
  
**工具运行截图**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR380icNfibmv7pgNpoia5Y69wxqreOOic00X4xASGh6xfUJyYrGGBemDduQppwJc2yUcqmhlnxVJSxAOJg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**许可证协议**  
  
  
  
本项目的开发与发布遵循  
BSD-3-Clause  
开源许可证协议。  
  
  
**项目地址**  
  
  
  
**route-detect：**  
  
https://github.com/mschwager/route-detect  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://owasp.org/Top10/A01_2021-Broken_Access_Control/  
> https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/  
> https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/  
> https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/  
> https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/  
> https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html  
> https://github.com/returntocorp/semgrep  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492995&idx=1&sn=cd4660fdf363a0173e2e8fa7f3879710&chksm=ce1f1f1cf968960ac99038a74f5ac2b9718e581753b97ff86f473ae80f1c2cc0e17fa3ed60de&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492835&idx=1&sn=a76625a0ed94ef9e3ccce9c92b384984&chksm=ce1f1e7cf968976aa3947aa7f69fe9318187d8160fa930c46e7347de2c2d7e1290164b0661e1&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
