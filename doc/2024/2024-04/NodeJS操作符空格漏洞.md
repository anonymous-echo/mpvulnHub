#  NodeJS操作符空格漏洞   
原创 repoog  洞源实验室   2024-04-19 18:06  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/gEGSydvbZs6Uds3atGRgfT4ITsXvvIhCt2fbOI4cE4q6ULyia7o9dTHpFJ6V5GHKgcpib9G51IfUia8gJZnytibF7Q/640?wx_fmt=gif "")  
  
**Node.js 是一个基于 Chrome V8 引擎的 JavaScript 运行环境**，它使得 JavaScript 可以脱离浏览器在服务器端运行。Node.js 利用事件驱动、非阻塞 I/O 模型等技术提高了性能，从而在开发领域得到广泛应用，比如Web服务应用（尤其是非阻塞的能力在I/O密集型应用上的应用），微服务架构的独立服务和RESTful API的开发，甚至是基于Electron的桌面应用程序也采用了NodeJS。  
  
多元的应用让JavaScript语言堪比世界上最好的开发语言PHP。  
  
作为开发语言，NodeJS在开发的应用中也会存在诸多其他与语言弱相关的安全漏洞，其类型包括功能实现类、安全功能类以及环境配置类。其中，功能实现类又包含常见的安全漏洞类型，包括命令执行（使用eval()或require()引入）、序列化漏洞、文件上传等等，以及NodeJS特有的供应链安全类漏洞，比如恶意的npm包的引入。  
  
 除此之外，还有一种是NodeJS语法本身特有的漏洞，即操作符空格漏洞。比如下方的示例代码：  
  
```
const session = require('express-session');
const express = require('express');
const app = express();


app.get('/secret', (req, res, next) => {
    if(req.session.guestǃ=true) {
        res.send("secret_string");
    } else {
       res.send("Not available to guests");
    }
})
```  
  
  
读到这里可以先暂停，仔细探究上述代码中的安全漏洞所在。这段代码曾经被我们作为多次招聘的题目，但遗憾的是没有人能够最终识别到正确的漏洞位置。  
  
  
  
  
  
  
  
  
  
  
  
答案揭晓：  
  
漏洞位置在于上述代码中的这行代码：  
```
if(req.session.guestǃ=true) {
```  
  
  
如果乍一看不太理解，我们可以先看理解下漏洞原理。  
  
在这行代码中，req.session.guest!=true没有留空格，导致req.session的对象guest!是赋值操作，判断语句始终为真。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs6Uds3atGRgfT4ITsXvvIhCucEeaTLFdRBqfY4IZFnE9GyPFS4mmG5TRIiaFnew737FJeHgKmGOibvw/640?wx_fmt=png "")  
  
漏洞原理非常简单，理解之后便很容易可以找到对应的修复方法，即采用强类型的操作符来做判断。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/gEGSydvbZs6Uds3atGRgfT4ITsXvvIhCpGF7jaCXD3XVoxrVwriaDPC9vLRa7qxMtRacdnojQL7UOUMTa9jsiawA/640?wx_fmt=png "")  
  
许多复杂的安全漏洞也如上述示例，如魔术一般，在揭示谜底之前显得尤为惊人和壮观，但了解谜底、恍然大悟之后，之后每每遇见同类手法便又显得索然无味。但与魔术不同的是，这样的“谜底”可以帮助开发人员和安全人员一次次避免可能导致的安全风险或安全漏洞。  
  
  
  
  
