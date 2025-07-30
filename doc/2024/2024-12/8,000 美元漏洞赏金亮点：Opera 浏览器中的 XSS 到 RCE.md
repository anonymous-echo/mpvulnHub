#  8,000 美元漏洞赏金亮点：Opera 浏览器中的 XSS 到 RCE   
 Ots安全   2024-12-21 07:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad09bHm9HtUPspREJrkVtb78gV9BjsSP667jnBwLqjKU88YJibKsl1qWf8DLUI9vG0Lz35dCYqKWRg/640?wx_fmt=jpeg&from=appmsg "")  
  
漏洞赏金猎人Renwa延续了之前的帖子，撰写了关于他向Opera 私人漏洞赏  
金计划提交的第二个漏洞：Opera 的 My Flow 功能中的远程代码执行。以下是他的写作和经验。当然，所描述的漏洞在报告后已立即得到修复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tad09bHm9HtUPspREJrkVtb7d0Tm3Vib5CRad21NKxibF8MCUWfviaO0rZJ79YrsF4AnyQNSbtfeKftLg/640?wx_fmt=png&from=appmsg "")  
  
Opera 浏览器的一个很酷的功能是My Flow，它基本上是您的计算机和手机之间的共享空间，允许您与自己共享链接、图像和视频。要连接，您只需扫描二维码，然后就可以在设备之间发送内容。  
  
使用 Opera 中的开发者工具，我发现 My Flow 界面是从域web.flow.opera.com加载的，这只是一个普通的 HTML 页面，并且允许我查看其代码和组件。  
  
查看该页面的源代码后，我发现该页面与浏览器扩展程序进行了通信，但从**opera://extensions/**中的浏览器扩展程序列表中，什么都没有出现。经过一番研究，我发现它实际上是一个隐藏的浏览器扩展程序，可以通过使用特殊标志**–show-component-extension-options**打开 Opera 来显示它。使用该标志打开浏览器后，我找到了名为**Opera Touch Background**的扩展程序，并能够查看其源代码。  
  
回到 web.flow.opera.com 页面，我开始寻找 XSS 漏洞。引起我注意的是以下代码：  
  
```
const html = e.dataTransfer.getData('text/html');
const src = html.match(//);
if (src && src[1]) {
   const parser = document.createElement("span");
   parser.innerHTML = src[1];
}
```  
  
  
此功能用于拖放；当用户将图像拖放到页面上时，代码会创建一个元素，并将其 innerHTML 元素设置为图像的位置。但是，这样做有两个问题：  
- 在浏览器中，可以将 dataTransfer 设置为任意值。  
  
- 在浏览器中，如果您创建一个新元素并将其 innerHTML 设置为 <img> 标签，它仍会在后台加载。  
  
这意味着尽管屏幕上没有加载任何图像，但以下操作仍会引发警告框：  
  
```
const parser = document.createElement("span");
parser.innerHTML = '<img src=x onerror=alert(1)>';
```  
  
  
考虑到所有这些，我创建了一个小型概念验证 XSS。为了展示引发 XSS 是多么容易，我创建了一个网页，一旦你开始拖动图像，几秒钟后就会重定向到 web.flow.opera.com 页面。这意味着用户只需开始拖动图像，然后松开鼠标，XSS 就会发生。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rWGOWg48tad09bHm9HtUPspREJrkVtb7PxgSdKKqKeORtxicKo3q7AMtY1XsEibRzbWHF4WxlVVMHvic3LCwtJcIw/640?wx_fmt=gif&from=appmsg "")  
  
但是，我想展示更大的影响，因此我开始研究 **Opera Touch Background** 扩展实际上做了什么。事实证明，它具有更高的权限，可以访问本机函数，例如**opr.operaTouchPrivate**，它是为与 My Flow 应用程序一起使用而开发的函数集合。查看可用的函数时，有两个案例引起了我的注意：**SEND_FILE**和**OPEN_FILE**。  
  
SEND_FILE 函数检索用户提供的文件信息并将其上传到 My Flow；它还将文件保存到用户计算机的Downloads/MyFlow中。OPEN_FILE 用于 My Flow 的图像文件，但在测试时我注意到您可以打开任何类型的文件，而不仅仅是图像。  
  
有了这两个功能，我们现在可以在目标计算机上写入和打开任意文件。为了创建一个真实的场景，我创建了一个概念验证，首先创建一个包含**calc的文件exploit.bat**，然后打开该文件 — — 这将导致它被执行，打开 Windows 计算器：  
  
```
operaTouchBackground.port.postMessage({
   type: "SEND_FILE",
   name: 'exploit.bat',
   content: 'calc',
   file_type: 'image/png'
});

operaTouchBackground.port.postMessage({
   type: 'OPEN_FILE',
   localFileName: 'exploit.bat'
});
```  
  
  
最后，通过令人信服的用户界面（只需单击（拖动）即可激活漏洞），我演示了如何为 My Flow 系统用户将简单的 XSS 转变为远程代码执行。  
  
  
该漏洞在几天内得到修复，大约三周后发放了赏金。  
  
感谢阅读！  
  
– Renwa  
  
赏金：8,000 美元。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
