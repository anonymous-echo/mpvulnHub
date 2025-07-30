#  vulnhuntr：基于大语言模型和静态代码分析的漏洞扫描与分析工具   
Alpha_h4ck  FreeBuf   2024-11-20 11:27  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于vulnhuntr**  
  
  
## vulnhuntr是一款基于大语言模型和静态代码分析的安全漏洞扫描与分析工具，该工具可以算得上是世界上首款具备自主AI能力的安全漏洞扫描工具。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38ov3d9VSRwd5RjPw2H7uhHIVyyIG7Mg3JcjcfGqibqOcH9iaRjHmWicuEZV1tdABRVQzsicXmicxaNXRA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Vulnhuntr 利用 LLM 的强大功能自动创建和分析整个代码调用链，从远程用户输入开始，到服务器输出结束，以检测复杂的、多步骤的和严重影响安全的漏洞，而这些漏洞，远远超出了传统静态代码分析工具的能力。  
##   
  
**功能介绍**  
  
##   
  
  
当前版本的vulnhuntr支持检测和识别以下漏洞类别：  
> 1、本地文件包含（LFI）  
> 2、任意文件覆盖（AFO）  
> 3、远程代码执行（RCE）  
> 4、跨站点脚本（XSS）  
> 5、SQL 注入（SQLI）  
> 6、服务器端请求伪造（SSRF）  
> 7、不安全的直接对象引用（IDOR）  
  
##   
  
**工具执行逻辑**  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38ov3d9VSRwd5RjPw2H7uhHJ5lBnhFnvgqtu2GjTdP4fMEDeH6f4THJctJW2W1VaL4oMU10QVfpNA/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**工具要求**  
  
  
##   
> Python v3.10  
  
##   
  
**工具安装**  
  
  
##   
  
由于该工具基于Python 3.10开发，因此我们首先需要在本地设备上安装并配置好Python 3.10环境。我们建议使用pipx或 Docker 轻松安装和运行 Vulnhuntr。  
###   
### Docker安装  
```
```  
```
docker build -t vulnhuntr https://github.com/protectai/vulnhuntr.git#main
```  
```
```  
### pipx安装  
```
```  
```
pipx install git+https://github.com/protectai/vulnhuntr.git --python python3.10
```  
```
```  
### 源码安装  
  
****```
```  
```
git clone https://github.com/protectai/vulnhuntr

cd vulnhuntr && poetry install
```  
```
```  
  
**工具使用**  
  
  
```
```  
```
usage: vulnhuntr [-h] -r ROOT [-a ANALYZE] [-l {claude,gpt,ollama}] [-v]

 

Analyze a GitHub project for vulnerabilities. Export your ANTHROPIC_API_KEY/OPENAI_API_KEY before running.

 

options:

  -h, --help             显示工具帮助信息和退出

  -r ROOT, --root ROOT  项目根目录的路径

  -a ANALYZE, --analyze ANALYZE

                        项目中要分析的特定路径或文件

  -l {claude,gpt,ollama}, --llm {claude,gpt,ollama}

                        要使用的LLM客户端（默认：claude）

  -v, --verbosity       增加输出的详细程度（-v表示INFO，-vv表示DEBUG）

```  
```
```  
  
**工具运行演示**  
  
  
## 使用 Claude 分析整个存储库：  
```
export ANTHROPIC_API_KEY="sk-1234"

vulnhuntr -r /path/to/target/repo/
```  
  
  
使用 GPT-4o 分析文件,也可以指定子目录而不是文件：  
```
export OPENAI_API_KEY="sk-1234"

vulnhuntr -r /path/to/target/repo/ -a server.py -l gpt
```  
  
  
使用 Claude 和自定义端点运行来分析 /local/path/to/target/repo/repo-subfolder/target-file.py：  
```
```  
```
docker run --rm -e ANTHROPIC_API_KEY=sk-1234 -e ANTHROPIC_BASE_URL=https://localhost:1234/api -v /local/path/to/target/repo:/repo vulnhuntr:latest -r /repo -a repo-subfolder/target-file.py
```  
```
```  
### 输出样例  
```
scratchpad:

Analyzing the add_llm function in llm_app.py. 2. Identified user input used as keys to access dictionaries: EmbeddingModel, ChatModel, RerankModel,

CvModel, and TTSModel. 3. These dictionaries contain class references, which are instantiated with user-supplied parameters. 4. The factory variable is

directly used from user input (req['llm_factory']) without proper validation. 5. The llm_name is also derived from user input in most cases. 6. The

instantiation of these classes occurs in try-except blocks, but exceptions are only used for error messages, not preventing execution. 7. The api_key

and other sensitive information are passed directly to these instantiated classes. 8. There's no comprehensive input validation or sanitization for the

factory or llm_name variables. 9. The vulnerability is in a route decorated with @login_required, indicating it's accessible to authenticated users. 10.

Reviewing the EmbeddingModel, ChatModel, RerankModel, CvModel, and TTSModel dictionaries to understand their contents and potential for exploitation.

----------------------------------------

 

analysis:

  The add_llm function in llm_app.py contains a critical Remote Code Execution (RCE) vulnerability. The function uses user-supplied input

(req['llm_factory'] and req['llm_name']) to dynamically instantiate classes from the EmbeddingModel, ChatModel, RerankModel, CvModel, and TTSModel

dictionaries. This pattern of using user input as a key to access and instantiate classes is inherently dangerous, as it allows an attacker to

potentially execute arbitrary code. The vulnerability is exacerbated by the lack of comprehensive input validation or sanitization on these

user-supplied values. While there are some checks for specific factory types, they are not exhaustive and can be bypassed. An attacker could potentially

provide a malicious value for 'llm_factory' that, when used as an index to these model dictionaries, results in the execution of arbitrary code. The

vulnerability is particularly severe because it occurs in a route decorated with @login_required, suggesting it's accessible to authenticated users,

which might give a false sense of security.

----------------------------------------

 

poc:

  POST /add_llm HTTP/1.1

  Host: target.com

  Content-Type: application/json

  Authorization: Bearer <valid_token>

  

  {

      "llm_factory": "__import__('os').system",

      "llm_name": "id",

      "model_type": "EMBEDDING",

      "api_key": "dummy_key"

  }

  

  This payload attempts to exploit the vulnerability by setting 'llm_factory' to a string that, when evaluated, imports the os module and calls system.

The 'llm_name' is set to 'id', which would be executed as a system command if the exploit is successful.

----------------------------------------

 

confidence_score:

  8

----------------------------------------

 

vulnerability_types:

  - RCE

----------------------------------------
```  
##   
  
**许可证协议**  
  
  
##   
  
本项目的开发与发布遵循  
AGPL-3.0  
开源许可协议。  
##   
  
**项目地址**  
  
  
##   
  
**vulnhuntr**：  
  
  
https://github.com/daniel2005d/mapXplore  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://protectai.com/threat-research/vulnhuntr-first-0-day-vulnerabilities  
> https://huntr.com/  
  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
