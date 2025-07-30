#  【burpsuite靶场-服务端3】目录遍历漏洞   
underatted  泷羽Sec-underatted安全   2025-02-01 03:08  
  
# 免责声明：  
  
由于传播、利用本公众号所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我会立即删除并致歉。谢谢！  
# 1. 简介  
  
在本节中，我们将解释什么是目录遍历，描述如何进行路径遍历攻击 和 绕过常见防护方式，并详细说明如何防范路径遍历漏洞。  
## 1.1 概念  
  
目录遍历（也称为文件路径遍历）是一个 Web 安全漏洞，它允许攻击者读取应用程序所在服务器上的任意文件。这可能包括应用程序代码和数据、后端系统的凭据 以及敏感的操作系统文件。在某些情况下，攻击者还能够向服务器上 写入任意文件，从而允许他们修改应用程序的数据或行为，并最终完全控制服务器。  
## 1.2 通过目录遍历读取任意文件  
  
思考，假如有一个显示待售商品图像的购物型 Web 应用程序。该图像通过一些 HTML 加载，如下所示：  
```
<img src="/loadImage?filename=218.png">
```  
  
loadImage  
的 URL 接受一个filename  
参数并返回指定文件的内容。图像文件本身存储在磁盘上的位置/var/www/images/  
中。为了返回图像，应用程序将请求的文件名追加到这个基目录，并使用文件系统 API 读取文件的内容。在上述情况中，应用程序将读取以下文件路径：  
```
/var/www/images/218.png
```  
  
该应用程序未对目录遍历攻击实施任何防御，因此攻击者可以请求以下 URL 并从服务器的文件系统中检索任意文件：  
```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```  
  
这将导致应用程序读取以下文件路径：  
```
/var/www/images/../../../etc/passwd
```  
  
序列../  
在文件路径中有效，表示在目录结构中向上提升一级。连续三个../  
序列将会从/var/www/images/  
一直上升到文件系统根目录，因此实际读取的文件是：  
```
/etc/passwd
```  
  
在基于 Unix 的操作系统上，这是一个标准文件，其中包含 在服务器上注册的用户详细信息。  
  
在 Windows 上，../  
和..\  
两者都是有效的目录遍历序列，用于检索标准操作系统文件的等效攻击是：  
```
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```  
### 实验 1 ：文件路径遍历，简单案例  
  
打开图片路径![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7JrBc1euDMrvJkgfZ1sibqdUWVnK17NH2NF1b8iboqhWIpJS7wnVn490g/640?wx_fmt=png&from=appmsg "")  
filename直接以文件名作为用户输入，使用相对路径，修改filename即可![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7vadKNzicntTezHmY1aPqsrQicOxZPQEC8odDfAewMKqnT6V2y8Z9Tn3A/640?wx_fmt=png&from=appmsg "")  
  
## 1.3 利用文件路径遍历漏洞时的常见阻碍  
### 实验2 ：文件路径遍历，使用绝对路径旁路阻止遍历序列  
  
许多将用户输入放置到文件路径中的应用程序实现了某种针对路径遍历攻击的防御，从而规避这些攻击。  
  
如果应用程序从用户提供的文件名中 剥离或阻止目录遍历序列，则可以使用各种技术绕过防御。  
  
您可以使用文件系统根目录中的绝对路径（例如filename=/etc/passwd  
）来直接引用文件，而无需使用任何遍历序列。  
  
同理，但是是利用绝对路径![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe70PdWUxsJLDcyljmrFKakVVj7AI9SeNPN5TDEy9Z60kfE8728ibOyDDA/640?wx_fmt=png&from=appmsg "")  
  
### 实验3：文件路径遍历，非递归剥离遍历序列  
  
有时，你可以使用嵌套的遍历序列，例如....//  
或....\/  
，当内部序列被剥离时，这些序列将恢复为简单的遍历序列。（双写绕过）![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7hd6LCCVg1azCFC94R23Ng5WkY4LJ8CP90CEichLhOhsNMmGHr0hv9eQ/640?wx_fmt=png&from=appmsg "")  
  
```
....//....//....//etc/passwd
```  
## 实验4：文件路径遍历，遍历序列剥离多余的URL解码  
  
在某些情况下，例如在 URL 路径或 multipart/form-data  
 请求的filename  
参数中，Web 服务器可能会在将输入传递到应用程序之前，剥离任何目录遍历序列。  
  
你有时可以通过 URL 编码，甚至双 URL 编码，基于../  
字符，分别生成%2e%2e%2f  
或%252e%252e%252f  
，从而绕过这种防护。还有各种非标准编码 也可以解决该问题，例如..%c0%af  
或..%ef%bc%8f  
。  
  
对于  
BurpSuite专业版 (opens new window)  
的用户，Burp Intruder 提供了一个预定义的有效负载列表（**Fuzzing - path traversal**  
），其中包含各种 编码后的路径遍历序列。  
  
前面步骤就不重复说了，直接将包发送到intruder![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7tnWfbChQZcRarhMYcwAFAaXCMoMjZRuGNic2ENRffJVntFtj0NSIPew/640?wx_fmt=png&from=appmsg "")  
BurpSuite 内置了一些常用字典，选择其中的 “Fuzzing - path traversal” ，这是用于路径遍历漏洞的模糊测试字典。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7IiawvibhB9YJfh2vWPMqAsC3tG3QnBibh6FicE9Q9icf6l7xWZ8NUeYjYEg/640?wx_fmt=png&from=appmsg "")  
找到 “Payload encoding” 配置项，将其中的 √ 取消勾选（默认是启用的）。 因为目录遍历的 攻击载荷 存在特殊字符，要防止其被编码。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7Xnt0RqUbxzBgTu5zYNkcibboW8LPQGwic1bwVQ3EqH40332g8dbxjkuQ/640?wx_fmt=png&from=appmsg "")  
成功![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7AKKSNhzlGVX7GunwjRmiaLyClSMzwXicBXZStXMvtIc4wD9HU77UZKKw/640?wx_fmt=png&from=appmsg "")  
拿去decode解码一下，发现进行了二次编码![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7zM5LW5tpj9KoictxADo9Zic1PuTZce7Nicc46fApDt7sCsdcQCpeJwRIg/640?wx_fmt=png&from=appmsg "")  
将hosts改成passwd即可通过实验。  
## 实验5：文件路径遍历，路径开始验证  
  
如果应用程序要求用户提供的文件名，必须以预期的基文件夹（例如/var/www/images  
）开头，则可以包含所需的基文件夹，然后再加上合适的遍历序列。例如：  
```
filename=/var/www/images/../../../etc/passwd
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7OXB8qVIpODKcIYTibC0g1bH0kHDXsjIuUlBtEQ3oaOhOXCGA4zvHI6Q/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe73FbeUdEjg59u0CJXKcbEZFwWD3dqEBRIAz28vDaS3GDqZZmrLDmmOg/640?wx_fmt=png&from=appmsg "")  
### 实验6：文件路径遍历-空字符绕过  
  
如果应用程序要求用户提供的文件名，必须以预期的文件扩展名（例如.png  
）结尾，则可以使用空字符，在所需扩展名之前 有效地终止文件路径。例如：  
```
filename=../../../etc/passwd%00.png
```  
  
添加多个扩展名，响应 无此文件![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7odsORTvCcoCvC8cj7icQrr83fnUPt8M5HxwFOO28ecNgNUqEXVlJk5Q/640?wx_fmt=png&from=appmsg "")  
  
  
在两个扩展名之间添加空字符，例如%00  
，形成41.jpg%00.jpg，图片正常显示。 说明第二个扩展名被忽略了，应用程序只识别了前面的  
65.jpg`。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7shzqUVq7Yn2O4vZ7c1mTPbp7g3T3r1rcNjjduJ1BNNBo8vVbBicOzfA/640?wx_fmt=png&from=appmsg "")  
  
  
同理，直接访问，../../../../etc/passwd显示无此文件![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7zLhsyZjlDu0Y16lgpLvGTrliccoq3O22fBg05mhXAvTouEQkMibzWxGA/640?wx_fmt=png&from=appmsg "")  
添加 空字符和扩展名，例如%00.jpg  
。![](https://mmbiz.qpic.cn/sz_mmbiz_png/zkFLzGMx1juAibotaU4Kt5LpicefZiaGUe7xY0qq2b27MWSGmABLuP2bTaPjfRqVlRBQ7NLzEa4nCibDibGP1KFibGpQ/640?wx_fmt=png&from=appmsg "")  
  
## 1.4 如何防范目录遍历攻击  
  
防范文件路径遍历漏洞的最有效方法是，避免将用户提供的输入完全传递给文件系统 API。可以重写许多应用程序的操作函数，以更安全的方式提供相同的行为。  
  
如果认为 将用户提供的输入 传递到文件系统 API 是不可避免的，则应该同时使用两层防御来防范攻击：  
- 应用程序应该在 处理用户输入之前 对其进行验证。理想情况下，验证应该与白名单进行比较。如果所需的功能无法实现这一点，则应该验证输入 是否仅包含允许的内容，例如纯字母 / 数字 / 字符。  
  
- 在验证提供的输入之后，应用程序应该将输入追加到基目录，并使用平台文件系统 API 规范化路径。它应验证规范化的路径 是否以预期的基目录开头。  
  
下面是一些简单的 Java 代码示例，用于 根据用户的输入 验证文件的规范路径：  
```
File file = new File(BASE_DIRECTORY, userInput);if (file.getCanonicalPath().startsWith(BASE_DIRECTORY)) {  // process file}
```  
  
  
  
