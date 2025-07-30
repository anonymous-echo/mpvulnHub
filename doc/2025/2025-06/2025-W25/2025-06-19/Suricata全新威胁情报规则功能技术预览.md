> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1MDA1MjcxMw==&mid=2649908301&idx=2&sn=4efd8f7893bdd09059139a9772c040a9

#  Suricata全新威胁情报规则功能技术预览  
原创 rayh4c  赛博攻防悟道   2025-06-19 00:31  
  
在当今瞬息万变的网络安全格局中，高效、精准、且富有上下文的威胁情报是防御体系的关键组成部分。传统的入侵检测系统（IDS）能够利用简单的指标（如IP地址或域名黑名单）进行匹配，但在提供深度上下文方面存在局限。它们能告诉我们“什么”发生了，却很少能解释“为什么”这很重要。Suricata，作为一款主流的开源网络威胁检测引擎，通过一项重要的新功能增强，正在应对这一挑战：**支持JSON的原生威胁情报数据集**  
。  
  
本文将深入探讨这一新功能，分析其如何将简单的指标匹配提升为上下文丰富的威胁检测，并通过剖析其底层实现，为安全分析师、威胁研究员和网络工程师提供一份详尽的技术预览。  
### 挑战：超越扁平化的指标列表  
  
长期以来，网络安全设备依赖于“信誉列表”或“数据集”来快速识别已知的恶意活动。这些列表通常是简单的文本文件，每行包含一个指标（IOC），例如一个恶意IP地址、一个已知的恶意软件文件哈希或一个C2域名。  
  
这种方法的优势在于速度快、资源占用低。然而，其局限性也同样明显：  
- **缺乏上下文：**  
 一个IP地址
```
1.2.3.4
```

  
出现在告警中，但它背后是什么？是勒索软件的C2服务器，还是一个普通的扫描源？其威胁等级如何？这个情报的可信度有多高？传统的列表无法回答这些问题。  
  
- **调查效率低下：**  
 分析师在收到告警后，必须手动查询各种外部威胁情报平台来补充上下文信息，这个过程耗时且容易出错。  
  
- **集成困难：**  
 现代威胁情报平台通常通过REST API提供丰富的JSON格式数据。将这些结构化数据“压平”成简单的文本列表，意味着丢失了宝贵的信息。  
  
为了解决这些痛点，Suricata需要对其规则语言进行扩展，使其能够理解和利用结构化的威胁情报。  
### Suricata的核心增强：引入JSON数据集  
  
Suricata的
```
dataset
```

  
规则关键字迎来了一次重大升级，它现在原生支持直接加载和解析JSON格式的威胁情报文件。这意味着安全团队可以将他们的情报源更顺畅地对接到Suricata的检测引擎中，而无需丢失关键的元数据。  
  
让我们看一个直观的对比：  
  
**传统方式 (CSV/列表):**  

```
# bad_domains.txt
evil-c2.com
malware-drop.net
phishing-site.org
```

  
对应的规则仅仅是进行“是/否”的判断：  

```
dns.query; dataset:isset,bad_domains;
```

  
  
**全新方式 (JSON):**  

```
// threat_feed.json
{
  &#34;provider&#34;: &#34;Threat-Intel-Corp&#34;,
  &#34;response&#34;: {
    &#34;threats&#34;: [
      {
        &#34;domain&#34;: &#34;evil-c2.com&#34;,
        &#34;threat_type&#34;: &#34;C2&#34;,
        &#34;malware_family&#34;: &#34;Cobalt Strike&#34;,
        &#34;confidence&#34;: 98,
        &#34;source_url&#34;: &#34;https://ti.example.com/report/123&#34;
      },
      {
        &#34;domain&#34;: &#34;malware-drop.net&#34;,
        &#34;threat_type&#34;: &#34;Malware-Distribution&#34;,
        &#34;malware_family&#34;: &#34;IcedID&#34;,
        &#34;confidence&#34;: 95,
        &#34;source_url&#34;: &#34;https://ti.example.com/report/124&#34;
      }
    ]
  }
}
```

  
通过新的规则语法，Suricata不仅能匹配，还能将所有上下文信息注入告警日志中。  
### 工作原理解析：一个端到端的示例  
  
为了充分理解这项功能的优势，让我们构建一个完整的检测流程。  
#### 第一步：准备威胁情报文件  
  
我们使用上文中的
```
threat_feed.json
```

  
文件。这是一个典型的API返回结构，其中包含一个嵌套的威胁对象数组。  
#### 第二步：编写Suricata规则  
  
我们创建一条规则，用于检测流向已知恶意域名的DNS查询。  

```
alert dns any any -> any any (msg:&#34;Threat Intel Match: Known Malicious Domain&#34;; \
    dns.query; \
    dataset:isset,malicious_domains, \
        type string, \
        load threat_feed.json, \
        format json, \
        value_key domain, \
        array_key response.threats, \
        context_key threat_info; \
    sid:900001; rev:1;)
```

  
让我们分解这条规则中
```
dataset
```

  
关键字的新参数：  
- **format json**  
明确告知Suricata这是一个JSON文件，需要使用JSON解析器进行处理。Suricata同样支持
```
ndjson
```

  
（换行符分隔的JSON），这对于流式或超大体积的情报文件更为高效。  
  
- **array_key response.threats**  
由于我们的情报数据嵌套在
```
{&#34;response&#34;: {&#34;threats&#34;: [...]}}
```

  
结构中，此参数使用点分路径（dot notation）指引Suricata找到真正的指标数组。  
  
- **value_key domain**  
指定在
```
threats
```

  
数组的每个对象中，用于匹配的键是
```
&#34;domain&#34;
```

  
。Suricata会提取所有
```
&#34;domain&#34;
```

  
的值（如"evil-c2.com"）来构建内存中的高性能哈希集。  
  
- **context_key threat_info**  
这是实现上下文丰富的核心。它指示Suricata，一旦匹配成功，就将**整个**  
匹配到的JSON对象（例如
```
{&#34;domain&#34;: &#34;evil-c2.com&#34;, ...}
```

  
）注入到告警的元数据中，并使用
```
&#34;threat_info&#34;
```

  
作为该注入对象的键。  
  
#### 第三步：分析EVE JSON告警  
  
当网络中出现对
```
evil-c2.com
```

  
的DNS查询时，上述规则会触发，并生成如下的EVE告警日志：  

```
{
  &#34;timestamp&#34;: &#34;2025-06-18T17:53:00.123456+0800&#34;,
  &#34;flow_id&#34;: 123456789,
  &#34;event_type&#34;: &#34;alert&#34;,
  ...
  &#34;alert&#34;: {
    &#34;action&#34;: &#34;allowed&#34;,
    &#34;gid&#34;: 1,
    &#34;signature_id&#34;: 900001,
    &#34;rev&#34;: 1,
    &#34;signature&#34;: &#34;Threat Intel Match: Known Malicious Domain&#34;,
    &#34;category&#34;: &#34;...&#34;,
    &#34;severity&#34;: 1,
    &#34;metadata&#34;: {
      &#34;threat_info&#34;: {
        &#34;domain&#34;: &#34;evil-c2.com&#34;,
        &#34;threat_type&#34;: &#34;C2&#34;,
        &#34;malware_family&#34;: &#34;Cobalt Strike&#34;,
        &#34;confidence&#34;: 98,
        &#34;source_url&#34;: &#34;https://ti.example.com/report/123&#34;
      }
    }
  },
  &#34;dns&#34;: {
    &#34;type&#34;: &#34;query&#34;,
    &#34;rrname&#34;: &#34;evil-c2.com&#34;
  },
  ...
}
```

  
请注意
```
alert.metadata
```

  
字段。
```
threat_info
```

  
对象被完整地添加了进来，为安全分析师提供了即时的、可操作的上下文。现在，分析师无需离开SIEM界面就能知道：  
- **是什么：**  
 这是一个已知的恶意域名。  
  
- **为什么：**  
 它与**Cobalt Strike**  
恶意软件家族的**C2**  
活动相关。  
  
- **可信度：**  
 情报源对此的置信度高达**98%**  
。  
  
- **下一步：**  
 可以立即访问
```
source_url
```

  
以获取更详细的分析报告。  
  
这极大地缩短了从告警到响应的决策时间，提升了整个安全运营（SOC）的效率。  
### 扩展应用：将情报关联到任意流量特征  
  
JSON数据集功能的真正威力在于其通用性。正如官方文档所述，
```
dataset
```

  
可以针对**任何粘滞缓冲区（sticky buffer）**  
进行匹配。这意味着几乎所有Suricata能从网络流量中提取的数据片段，都可以作为关键字来查询您的上下文威胁情报库。这为超越简单域名或IP匹配的先进检测策略开启了广阔空间。  
  
让我们探讨一些跨协议的强大应用场景：  
#### 1. TLS/SSL证书与通信指纹  
  
在TLS握手元数据上进行匹配是检测加密C2通信最有效的方法之一。  
- **SNI (服务器名称指示)**  

```
tls.sni; dataset:isset,suspicious_sni, ...;
```

  
  
您可以维护一个已知恶意或可疑SNI值的数据集，并用相关的威胁参与者或攻击活动信息来丰富告警。  
  
- **证书指纹**  

```
tls.cert_fingerprint; dataset:isset,compromised_certs, ...;
```

  
  
通过加载一个包含已知被盗用或滥用的自签名证书的SHA-1指纹数据集，您可以立即识别出恶意的TLS会话，并用证书不被信任的具体原因来丰富告警。  

```
// compromised_certs.json
{
  &#34;certs&#34;: [
    {
      &#34;fingerprint&#34;: &#34;a1b2c3d4e5f6...&#34;,
      &#34;reason&#34;: &#34;Revoked by CA for misuse&#34;,
      &#34;threat_actor&#34;: &#34;APT29&#34;
    }
  ]
}
```

  
相应的规则将使用 
```
value_key: fingerprint
```

  
 和 
```
array_key: certs
```

  
。  
  
- **JA3/JA3S 指纹**  

```
tls.ja3.hash; dataset:isset,known_malware_ja3, ...;
```

  
  
针对与特定恶意软件（如Cobalt Strike、Metasploit）关联的JA3哈希值数据集进行匹配，即使其C2服务器的IP和域名不断变化，也能实现高度可靠的恶意工具识别。JSON上下文可以提供该恶意软件的明确名称。  
  
#### 2. HTTP流量特征  
  
除了
```
http.host
```

  
，数据集还可以应用于众多其他HTTP字段。  
- **User-Agent**  

```
http.user_agent; dataset:isset,bad_user_agents, ...;
```

  
  
检测已知的恶意或非典型User-Agent字符串。JSON上下文可以指明其所属的僵尸网络名称，或解释为何该UA被视为恶意（例如，“已知的Python-requests脚本型僵尸网络”）。  
  
- **URI路径**  

```
http.uri; dataset:isset,malicious_uris, ...;
```

  
  
维护一个已知被用于漏洞利用或C2回调的URI路径列表（例如 
```
/api/v1/gate.php
```

  
）。上下文可以描述其针对的特定漏洞或关联的恶意软件。  
  
#### 3. 文件哈希与恶意软件分析  
  
这是一个经典用例，现在通过上下文得到了极大的增强。  
- **文件哈希**  

```
file.sha256; dataset:isset,malware_hashes, ...;
```

  
  
当Suricata从流量中提取文件时（例如从HTTP、SMB、SMTP），它可以计算其哈希值。将这些哈希值与JSON数据集进行匹配，可以即时提供丰富的恶意软件情报。  

```
// malware_hashes.json
[
    {
      &#34;sha256&#34;: &#34;f1e2d3c4b5a6...&#34;,
      &#34;family&#34;: &#34;Emotet&#34;,
      &#34;type&#34;: &#34;Dropper&#34;,
      &#34;threat_level&#34;: 5
    }
]
```

  
由此产生的EVE日志将立即告诉分析师，他们正在处理一个Emotet下载器，其威胁级别以及其他相关数据，从而实现更快、更准确的响应。  
  
#### 4. DNS查询分析  
  

```
dns.query
```

  
缓冲区是一个主要的应用目标，但可以与其他关键字结合使用以实现更精细的匹配。  
- **结合 pcrexform 提取顶级域名 (TLD)**  

```
dns.query; pcrexform:&#34;/\\.([^\\.]+)$/&#34;; dataset:isset,suspicious_tlds, ...;
```

  
  
您可以创建一个可疑顶级域名（如 .xyz, .top, .pw）的数据集，并用解释该TLD为何被认为是高风险的信息来丰富告警（例如，“常被用于网络钓鱼活动”）。  
  
这些示例仅仅是冰山一角。将任何粘滞缓冲区用作查找关键字的能力，使
```
dataset
```

  
功能从一个简单的黑名单机制，转变为位于Suricata核心的、动态的、跨协议的威胁情报关联引擎。  
### 技术实现深度解析  
  
基于对Suricata源代码的分析，我们可以揭示其背后严谨而高效的设计。这个功能的核心逻辑主要分布在 
```
detect-dataset.c
```

  
、
```
datasets.c
```

  
 和 
```
datasets-context-json.c
```

  
 三个文件中。  
#### 1. 模块化架构与责任分离  
  
Suricata通过清晰的模块划分来管理数据集功能：  
- **datasets.c & datasets.h**  
提供了数据集管理的**通用框架**  
。它定义了 
```
Dataset
```

  
 结构体和核心API，如 
```
DatasetGet()
```

  
（获取或创建数据集）、
```
DatasetLookup()
```

  
（查找）和 
```
DatasetAdd()
```

  
（添加），并处理内存管理、锁定和非JSON格式的数据加载。  
  
- **datasets-context-json.c & datasets-context-json.h**  
**JSON功能的专门实现**  
。它建立在通用框架之上，负责解析JSON/NDJSON文件、提取键值对以及管理与每个指标关联的JSON上下文。  
  
- **detect-dataset.c & detect-dataset.h**  
:作为**规则引擎和数据集模块之间的桥梁**  
。它负责解析规则中的
```
dataset
```

  
关键字，并根据解析出的参数（特别是
```
format
```

  
）来决定调用通用加载逻辑还是JSON专用加载逻辑。  
  
- **unix-manager.c**  
实现了Unix Socket的命令处理，为数据集的**动态更新**  
提供了运行时接口。  
  
#### 2. 规则解析与分发（detect-dataset.c）  
  
当Suricata启动并加载规则时，
```
DetectDatasetSetup
```

  
 函数被触发。  
1. **参数解析**  
: 首先，
```
DetectDatasetParse
```

  
 函数被调用，它像一个小型词法分析器，使用 
```
strtok_r
```

  
 来分割逗号分隔的
```
dataset
```

  
参数字符串。它会识别并填充 
```
format
```

  
、
```
value_key
```

  
、
```
context_key
```

  
 等关键变量。  
  
1. **合法性检查**  
: 代码会进行严格的检查，例如，如果
```
format
```

  
是
```
json
```

  
，那么
```
set
```

  
或
```
unset
```

  
命令是不允许的，因为这些数据集被设计为只读（由外部情报源管理）。  
  
1. **逻辑分发**  
: 这是最关键的一步。
```
DetectDatasetSetup
```

  
 函数检查
```
format
```

  
变量。  
  
1. 如果
```
format
```

  
是默认的
```
csv
```

  
，它会调用 
```
DatasetGet()
```

  
 (`datasets.c`)。  
  
1. 如果
```
format
```

  
是
```
json
```

  
或
```
ndjson
```

  
，它会调用 **DatajsonGet() (`datasets-context-json.c`)**  
。 这个决策点将控制流从通用实现引导至专门的JSON处理模块。  
  
#### 3. 数据加载与存储（datasets-context-json.c）  
  

```
DatajsonGet
```

  
 函数是JSON数据集加载的核心。  
1. **底层依赖**  
:它依赖于轻量级的C语言JSON库 **jansson**  
 来完成所有解析任务。  
  
1. **文件格式处理**  
1. **JSON**  
对于
```
format: json
```

  
，
```
DatajsonLoadTypeFromJSON
```

  
 -> 
```
ParseJsonFile
```

  
 会使用 
```
json_load_file()
```

  
 一次性加载整个文件。然后，如果提供了
```
array_key
```

  
，
```
GetSubObjectByKey
```

  
会像剥洋葱一样，根据点分路径（如 
```
response.threats
```

  
）深入JSON结构，找到包含情报指标的数组。  
  
1. **NDJSON**  
对于
```
format: ndjson
```

  
，
```
DatajsonLoadTypeFromJsonline
```

  
 则采用更节省内存的方式，通过
```
fgets
```

  
逐行读取文件，并将每一行作为独立的JSON对象处理。  
  
1. **数据提取与存储**  
1. 在获取到包含指标的JSON对象（或数组中的每个对象）后，
```
DatajsonAdd...Element
```

  
 函数（如
```
DatajsonAddStringElement
```

  
）会使用 
```
GetSubObjectByKey
```

  
 和 
```
json_string_value
```

  
，根据
```
value_key
```

  
提取出用于匹配的**键**  
（例如 "evil-c2.com"）。  
  
1. 随后，
```
DatajsonSetValue
```

  
 函数会将**整个JSON对象**  
（即附带的上下文）通过
```
json_dumps()
```

  
重新序列化为一个字符串。  
  
1. 最后，
```
DatajsonAdd
```

  
 函数将 **[匹配键, 上下文字符串]**  
 这个键值对存入内存中的高性能哈希表 
```
THashTableContext
```

  
。这确保了在O(1)的时间复杂度内完成查找，同时保留了完整的上下文信息。  
  
#### 4. 实时匹配与告警注入（detect-dataset.c）  
  
当网络流量进入检测流程时：  
1. **匹配触发**  
规则中的
```
dns.query
```

  
等关键字从流量中提取出待查数据（例如域名 "evil-c2.com"）。  
  
1. **查找**  

```
DetectDatasetBufferMatch
```

  
 函数被调用，它检查数据集格式并调用
```
DetectDatajsonBufferMatch
```

  
。此函数的核心是调用 
```
DatajsonLookup()
```

  
 (datasets-context-json.c)，在哈希表中查找提取出的域名。  
  
1. **上下文检索与注入**  
1. 如果
```
DatajsonLookup
```

  
命中，它不仅返回
```
found = true
```

  
，还会返回一个
```
DataJsonResultType
```

  
结构体，其中包含了之前存储的、完整的JSON上下文信息字符串。  
  
1. 
```
DetectDatajsonBufferMatch
```

  
拿到这个字符串后，会获取当前线程的告警上下文
```
det_ctx->json_content
```

  
。  
  
1. 它使用
```
snprintf
```

  
将规则中定义的
```
context_key
```

  
（如 "threat_info"）和检索到的JSON字符串，动态地构建成一个最终告警日志中的新字段。
```
snprintf(..., &#34;\&#34;%s\&#34;:%s&#34;, sd->json_key, r.json.value);
```

  
 这行代码是该功能的核心实现之处。  
  
1. 最终，这个新字段会出现在EVE日志的
```
alert.metadata
```

  
对象中。  
  
#### 5. 动态更新能力（unix-manager.c）  
  
为了实现情报的敏捷性，Suricata允许在不中断服务的情况下更新数据集：  
1. **命令注册**  
在
```
UnixManagerInit
```

  
中，命令
```
dataset-add-json
```

  
被注册，并将其处理函数指向
```
UnixSocketDatajsonAdd
```

  
。  
  
1. **实时处理**  
当管理员通过
```
suricatasc
```

  
工具发送该命令时，
```
UnixSocketDatajsonAdd
```

  
负责解析传入的参数，包括数据集名称、指标值和要关联的JSON上下文。  
  
1. **调用核心API**  
它最终会调用DatajsonAddSerialized (  
datasets-context-json.c)，该函数将字符串形式的指标和JSON上下文反序列化（如有必要），并调用
```
DatajsonAdd
```

  
将新情报实时地、线程安全地添加到内存中的哈希表中。  
  
### 结论：迈向更智能的威胁检测  
  
Suricata的JSON数据集功能是一项重要的功能增强，标志着开源网络威胁检测在灵活性和自动化方面取得了显著进展。通过原生支持结构化的威胁情报，Suricata正在弥补传统IDS在告警上下文方面的不足。  
  
  
