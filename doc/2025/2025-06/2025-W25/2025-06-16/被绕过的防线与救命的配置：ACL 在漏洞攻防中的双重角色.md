> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA3MTUxNzQxMQ==&mid=2453886078&idx=1&sn=8afe4da7c70f074d8c565ddbe7938c09

#  被绕过的防线与救命的配置：ACL 在漏洞攻防中的双重角色  
让数据更安全  德斯克安全小课堂   2025-06-16 03:16  
  
在现代网络安全领域，访问控制列表（ACL，Access Control Lists）作为一种基础且高效的安全机制，被广泛应用于网络设备和主机系统中，用于控制数据流和资源访问。然而，随着网络环境日益复杂与攻击手段不断演进，ACL 的配置、管理与实现面临诸多挑战。本文将深入探讨 ACL 在网络安全实践中的应用，结合近期 ACL 绕过类漏洞与 ACL 修复真实案例，并结合 FreeBuf 和看雪论坛中的实战内容，提出更贴近实践的最佳建议，适合初学者理解~  
## 一、ACL 的背景与工作原理  
### 1.1 什么是 ACL？  
  
ACL 是一种基于包过滤的访问控制技术，它根据预先定义的规则，对通过网络设备的数据包进行检查和过滤，决定是否允许通过或拒绝。ACL 主要应用于路由器和三层交换机，作用包括限制网络流量、提高网络性能、控制通信流量以及提供网络安全的基本手段。  
  
- **标准 ACL**  
：基于源 IP 地址，编号为 1-99。例如，只允许特定 IP 地址访问网络。  
  
- **扩展 ACL**  
：基于源/目的 IP 地址、协议、端口等，编号为 100-199。例如，允许特定 IP 地址通过 HTTP 协议访问服务器。  
  
  
  
ACL 的工作原理是，当数据包到达网络设备时，设备会按照 ACL 规则的顺序逐一检查，直到找到匹配的规则为止。如果没有匹配的规则，数据包将被默认拒绝（隐含的“deny any”规则）。  
  
**示例配置**  
：  

```
access-list 101 deny tcp host 192.168.1.100 any eq 80
access-list 101 permit ip any any
interface GigabitEthernet0/0
 ip access-group 101 in
```

  
此配置拒绝来自 192.168.1.100 的 HTTP 流量（端口 80），允许其他流量。  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/c5fPvg33s0GiaicJouY9ST9RibMc84Gibia2aicCFDSh4bhscCTvFaJkI9kkrrsxxIaA4vvJHBFlqvR1eb990c1Ld7xg/640?wx_fmt=jpeg&from=appmsg "")  
  
### 1.2 ACL 在网络安全中的重要性  
  
ACL 是网络安全的核心工具之一，它通过控制流量，保护网络资源免受未授权访问。例如，企业可以使用 ACL 限制特定 IP 地址或端口的访问，防止恶意流量进入网络。然而，ACL 的有效性依赖于正确的配置和管理，任何实现缺陷都可能被攻击者利用，导致安全漏洞。  
!  
### 1.3 相关技术背景  
  
- **MPLS（多协议标签交换）**  
：一种基于标签的路由技术，通过短标签而非长地址进行数据转发，广泛用于服务提供商网络。  
  
- **伪线（Pseudowire, PW）**  
：在分组交换网络上模拟点对点连接，常用于 MPLS 网络中连接客户站点。  
这些技术与 ACL 的结合增加了配置复杂性，也为漏洞提供了可乘之机。  
  
  
## 二、ACL 绕过类漏洞的深入分析  
  
ACL 绕过类漏洞通常源于设备或系统底层实现缺陷，攻击者可以利用这些缺陷突破访问控制，访问原本受限的资源。以下是近年发现的典型案例，结合实战提示和修复建议：  
### 2.1 CVE-2024-20315（Cisco IOS XR MPLS 接口 ACL 绕过）  
  
- **背景与原因**  
：  
Cisco IOS XR 在 MPLS ingress 接口启用了 ACL 后，因内部接口上下文与查找键（lookup key）关联错误，导致数据包通过 MPLS 标签处理绕过 ACL 检测，从而绕过安全策略。  
  
- **影响**  
：  
攻击者可通过发送特制 MPLS 封装包，访问本应被 ACL 阻止的资源，可能导致数据泄露或服务中断。  
  
- **影响版本**  
：  
7.9、7.10 等旧版本，7.8、7.11 未受影响。  
  
- **漏洞复现示例**  
：  
攻击者构造以下数据包：  
  
  

```
Ethernet / MPLS(label=1000) / IP(src=10.0.0.5, dst=10.1.1.1) / TCP(sport=12345, dport=80) / Payload
```

  
假设 ACL 配置为：  

```
access-list 101 deny ip host 10.0.0.5 any
access-list 101 permit ip any any
interface MPLS0/0
 ip access-group 101 in
```

  
由于 MPLS 标签处理缺陷，数据包绕过 ACL 检查，直接到达目标 10.1.1.1。  
  
- **实战提示**  
：  
在复杂协议栈中，如 MPLS 环境，ACL 的匹配过程与 lookup 逻辑紧密耦合。如果数据封装顺序意外绕过查找逻辑，ACL 可能失效。这与一些 VPN、SSL VPN 中间人攻击绕过 ACL 的原理类似，例如通过篡改设备下发的端口列表绕过客户端 ACL 。  
  
- **修复建议**  
：  
  
  

```
interface MPLS0/0
```

  
- **首选方案**  
：升级至 IOS XR 7.9.1、7.9.2、7.10.2 或更高版本，修复底层逻辑缺陷。  
  
-     - **临时措施**  
：移除 MPLS ingress ACL，改在 egress 方向部署 ACL 策略（适用于 7.6.2 及以上版本）。需验证业务兼容性，例如：  
  
  
  
- **临时措施**  
：移除 MPLS ingress ACL，改在 egress 方向部署 ACL 策略（适用于 7.6.2 及以上版本）。需验证业务兼容性，例如：  
  
  

```
no ip access-group 101 in
interface GigabitEthernet0/1
ip access-group 101 out
```

### 2.2 CVE-2024-20322（Cisco IOS XR PW-Ether 接口 ACL 绕过）  
  
- **背景与原因**  
：  
与 CVE-2024-20315 类似，但发生在 PW-Ether（以太网伪线）接口，同样因 lookup key 处理不当造成 ingress ACL 失效。  
  
- **影响**  
：  
攻击者可访问受限资源，影响伪线连接的安全性。  
  
- **影响版本**  
：  
7.10、7.11 等版本，需升级至最新补丁。  
  
- **漏洞复现示例**  
：  
配置如下 CLI：  
  
  

```
interface PW-Ether1
  ipv4 access-group DENY_ACL ingress
! DENY_ACL 定义
ipv4 access-list DENY_ACL
 10 deny ip host 172.16.0.5 any
 20 permit ip any any
```

  
攻击者发送以下数据包：  

```
Ethernet / PW-Ether / IP(src=172.16.0.5, dst=192.168.1.1) / TCP(sport=54321, dport=443) / Payload
```

  
由于查找键错误，数据包绕过 ACL，访问目标 192.168.1.1。  
  
- **实战**  
：  
此类问题常出现在协议重封装和隧道环境下，如 VPN Server 下行的端口 ACL 表更新可被中间人改写，提示 ACL 在多重协议逻辑接口上尤为脆弱。  
  
- **修复方法**  
：  
  
-     - 升级至 7.10.2 或 7.11.2+。  
  
    - 无有效临时措施，建议隔离受影响接口并尽快部署补丁。  
  
  
  
- 升级至 7.10.2 或 7.11.2+。  
  
- 无有效临时措施，建议隔离受影响接口并尽快部署补丁。  
  
  
### 2.3 CVE-2023-20191（Cisco IOS XR MPLS ingress ACL 缺陷）  
  
- **缺陷点**  
：  
当启用 ingress ACL 时，对显式空标签（explicit null）或标签解聚合（deaggregation）的处理存在缺陷，ACL deny 规则失效，数据包被错误转发 。  
  
- **影响**  
：  
攻击者可通过构造带 explicit-null 标签的包，绕过 ACL，访问受限资源。  
  
- **漏洞复现示例**  
：  
配置如下：  
  
  

```
ipv4 access-list MPLS_ACL
 10 deny ip any host 10.10.10.10
 20 permit ip any any
interface MPLS0/0
 ipv4 access-group MPLS_ACL ingress
```

  
攻击者发送：  

```
Ethernet / MPLS(label=0, explicit-null) / IP(src=192.168.2.2, dst=10.10.10.10) / Payload
```

  
数据包因标签处理缺陷被转发至 10.10.10.10。  
  
- **实战**  
：  
攻击者可利用多层隧道协议（如 GRE over MPLS）构造类似数据包，增加绕过成功率。  
  
- **修复建议**  
：  
  
  

```
interface MPLS0/0
```

  
- 升级至 7.7.21、7.9.2、7.10.1，或应用对应 SMU 补丁。  
  
-     - 临时移除 ingress ACL，改用 egress ACL：  
  
  
  
- 临时移除 ingress ACL，改用 egress ACL：  
  
  

```
no ipv4 access-group MPLS\_ACL ingress
interface GigabitEthernet0/1
ipv4 access-group MPLS\_ACL out
```

### 2.4 CVE-2023-20190（经典 ACL 压缩功能缺陷）  
  
- **问题描述**  
：  
Cisco IOS XR ACL 压缩模块在编码目标地址范围时异常，压缩后的行为与原 ACL 定义不一致，导致 deny 条件失效 。  
  
- **影响**  
：  
攻击者可利用疏漏的 deny 规则访问受限网络。  
  
- **漏洞示例**  
：  
原 ACL：  
  
  

```
ipv4 access-list COMP_ACL
 10 deny ip host 192.168.100.100 any
 20 permit ip any any
```

  
压缩后，
```
192.168.100.100
```

  
的 deny 规则被忽略，攻击者可通过该地址访问网络。  
  
- **实战**  
：  
常见于为提升性能启用 ACL 压缩的设备，建议避免使用压缩功能或定期验证压缩后规则。  
  
- **修复方法**  
：  
  
  

```
no ipv4 access-list COMP_ACL
```

  
- 升级至带补丁的版本。  
  
-     - 禁用经典压缩，使用 SVR 模式 ACL：  
  
  
  
- 禁用经典压缩，使用 SVR 模式 ACL：  
  
  

```
ipv4 access-list SVR\_ACL
10 deny ip host 192.168.100.100 any
20 permit ip any any
```

## 三、通过 ACL 配置修复的真实案例  
  
ACL 不仅用于防御，还可作为修复漏洞的临时或永久手段。以下是两个典型案例：  
### 3.1 CVE-2021-36934 “SeriousSAM” 补丁  
  
- **背景与风险**  
：  
Windows 默认允许用户对 SAM、SECURITY、SYSTEM 等 hive 文件在 shadow copy 中读访问，攻击者可能读取敏感信息，如用户凭据。  
  
- **解决方案**  
：  
使用 
```
icacls
```

  
强制继承权限，仅允许 SYSTEM 和 Administrators 访问，并移除 shadow copies：  
  
  

```
icacls C:\Windows\System32\config\*.* /inheritance:e
vssadmin delete shadows /all /quiet
Checkpoint-Computer -Description &#34;After SeriousSAM fix&#34; -RestorePointType MODIFY_SETTINGS
```

  
社区反馈表示，该脚本在约 605 台 Win10 设备上执行后无异常，验证了其可靠性。  
  
- **验证示例**  
：  
  
  

```
Get-Acl C:\Windows\System32\config\SAM | Select-Object Path, AreAccessRulesProtected
```

  
输出 
```
AreAccessRulesProtected
```

  
为 
```
False
```

  
，表示继承关闭，ACL 修复成功。  
  
- **实战启发**  
：  
FreeBuf 提到，攻击者可拦截服务端下发的 ACL 列表（如端口范围），进行中间人篡改，绕过客户端 ACL 检查，提醒设计 ACL 策略时需全面考虑通信流程 。  
  
  
### 3.2 CVE-2020-0674 JavaScript 引擎漏洞缓解  
  
- **背景与风险**  
：  
IE JavaScript 引擎漏洞允许远程执行恶意脚本，厂商建议通过 ACL 限制 
```
jscript.dll
```

  
的访问权限 。  
  
- **解决方案**  
：  
  
  

```
icacls &#34;%PROGRAMFILES%\Internet Explorer\jscript.dll&#34; /deny &#34;Users:(R)&#34;
icacls &#34;%PROGRAMFILES%\Internet Explorer\jscript.dll&#34; /grant &#34;Administrators:(R,X)&#34;
```

  
移除普通用户的读权限，仅允许管理员读取和执行，阻止未授权脚本利用漏洞。  
  
- **说明**  
：  
虽然非完备修复，但通过 ACL 控制降低攻击面，适用于无法立即升级的场景。  
  
  
## 四、ACL 在网络安全实践中的挑战与现状  
  
当前，ACL 的应用面临以下挑战，亟需结合实际环境优化策略：  
  
1. **最小权限原则的实现难度**  
在大型网络中，精确配置 ACL 既复杂又耗时。过宽的规则可能导致安全漏洞，过严则可能阻断合法业务流量。例如，企业常因业务需求临时放宽 ACL，却未及时回滚，增加暴露风险。  
  
1. **入站 ACL 的普遍缺陷**  
如 Cisco IOS XR 案例所示，许多平台的入站 ACL 实现存在缺陷，尤其在处理 MPLS 或伪线接口时。这提示我们在设计网络时需谨慎选择 ACL 部署位置。  
  
1. **配置与底层实现的脱节**  
ACL 的实际效果不仅取决于配置，还与设备固件或操作系统的处理逻辑密切相关。未经审计的底层变更（如固件升级）可能导致 ACL 失效。  
  
1. **管理复杂性与自动化需求**  
随着网络规模扩大，手动管理 ACL 变得低效且易出错。现代企业逐渐转向自动化工具（如 Ansible、SDN 控制器）来动态调整 ACL，但这也引入了新的复杂性和潜在风险。  
  
1. **动态环境与可扩展性**  
在云环境或 IoT 设备增多的情况下，ACL 需适应频繁变化的 IP 地址和设备，管理难度增加。  
  
1. **性能与安全性的平衡**  
复杂的 ACL 可能影响网络性能，需优化规则以减少处理开销。例如，合并相似的 ACL 条目或使用硬件加速。  
  
1. **可见性与监控**  
缺乏日志和监控工具，难以实时发现 ACL 绕过或配置错误。建议结合 SIEM 系统进行事件分析。  
  
  
## 五、结语与最佳实践  
  
ACL 作为网络安全的核心组件，其正确使用对保护资源至关重要。结合上述案例与现状，以下是更贴近实践的最佳建议：  
  
1. **遵循最小权限原则**  
确保 ACL 规则精确匹配需求，避免使用过于宽泛的 
```
permit any
```

  
规则。建议为每条规则添加注释，记录用途，便于后续审查。例如：  
  
  

```
ipv4 access-list SECURE_ACL
 10 deny ip host 192.168.1.100 any ! Block malicious host
 20 permit tcp any host 192.168.1.200 eq 443 ! Allow HTTPS to server
```

  
1. **优先评估入站与出站策略**  
在入站 ACL 存在已知缺陷的平台上（如 Cisco IOS XR 早期版本），优先考虑出站 ACL，或结合防火墙规则增强防护。  
  
1. **定期审计与测试**  
每月检查 ACL 配置的有效性，使用模拟流量测试 
```
deny
```

  
规则是否生效。例如，使用工具如 
```
nmap
```

  
扫描受限端口。  
  
1. **及时应用补丁与升级**  
对网络设备（如 Cisco IOS XR）或主机系统（如 Windows），建立补丁管理流程，确保 ACL 相关漏洞及时修复。  
  
1. **整合监控与分析工具**  
部署 SIEM 系统或 NetFlow 分析工具，实时监控 ACL 拒绝事件，快速识别绕过尝试。例如，通过日志分析发现异常流量模式后，可立即优化 ACL 规则。  
  
1. **引入自动化管理**  
对于复杂网络，借助自动化工具（如 Cisco ACI 或脚本）动态生成和部署 ACL，减少人为失误，同时提升响应速度。例如，使用 Ansible 脚本批量更新 ACL：  
  
  

```
- name: Apply ACL to Cisco IOS XR
  cisco.iosxr.iosxr_acl:
    config:
      acls:
        - name: SECURE_ACL
          aces:
            - sequence: 10
              deny:
                protocol: ip
                source:
                  host: 192.168.1.100
                destination:
                  any: true
            - sequence: 20
              permit:
                protocol: tcp
                source:
                  any: true
                destination:
                  host: 192.168.1.200
                  port_protocol:
                    eq: 443
    state: merged
```

  
通过以上实践，安全团队可以更高效地利用 ACL，应对日益严峻的网络威胁，确保业务安全与连续性。  
## 六、附录：ACL 配置与漏洞影响总结  
<table><thead><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid #cccccc;border-right: 1px solid #cccccc;border-bottom: none;border-left: 1px solid #cccccc;border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: #f5f5f5;"><strong><span leaf="">漏洞编号</span></strong></th><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid #cccccc;border-right: 1px solid #cccccc;border-bottom: none;border-left: 1px solid #cccccc;border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: #f5f5f5;"><strong><span leaf="">影响接口</span></strong></th><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid #cccccc;border-right: 1px solid #cccccc;border-bottom: none;border-left: 1px solid #cccccc;border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: #f5f5f5;"><strong><span leaf="">主要问题</span></strong></th><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid #cccccc;border-right: 1px solid #cccccc;border-bottom: none;border-left: 1px solid #cccccc;border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: #f5f5f5;"><strong><span leaf="">修复版本</span></strong></th><th style="box-sizing: border-box;text-align: center;margin: 0px;padding: 0px;border-top: 1px solid #cccccc;border-right: 1px solid #cccccc;border-bottom: none;border-left: 1px solid #cccccc;border-image: initial;text-decoration: none;font-style: inherit;font-variant: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;background: #f5f5f5;"><strong><span leaf="">临时措施</span></strong></th></tr></thead><tbody><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">CVE-2024-20315</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">MPLS</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">Lookup key 错误，ACL 绕过</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">7.9.1, 7.9.2, 7.10.2+</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">使用 egress ACL</span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">CVE-2024-20322</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">PW-Ether</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">Lookup key 错误，ACL 绕过</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">7.10.2, 7.11.2+</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">无，需升级</span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">CVE-2023-20191</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">MPLS</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">Explicit-null 处理缺陷</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">7.7.21, 7.9.2, 7.10.1+</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">使用 egress ACL</span></section></td></tr><tr style="box-sizing: border-box;margin: 0px;padding: 0px;border: 0px;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;"><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">CVE-2023-20190</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">任意（压缩 ACL）</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">压缩后 deny 规则失效</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">最新补丁版本</span></section></td><td style="box-sizing: border-box;margin: 0px;padding: 5px;border: 1px solid #cccccc;text-decoration: none;font-style: inherit;font-variant: inherit;font-weight: inherit;font-stretch: inherit;font-size: inherit;line-height: inherit;font-optical-sizing: inherit;font-size-adjust: inherit;font-kerning: inherit;font-feature-settings: inherit;font-variation-settings: inherit;vertical-align: baseline;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, &#34;WenQuanYi Micro Hei&#34;, PingFangSC;outline: none;text-align: left;word-break: break-word;white-space: pre-wrap;"><section><span leaf="">禁用压缩，使用 SVR 模式</span></section></td></tr></tbody></table>  
**示例**  
（CVE-2024-20315）：  

```
Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Ethernet II, Src: 00:50:56:c0:00:01, Dst: 00:50:56:c0:00:02
MPLS Label Stack, Label: 1000, Exp: 0, S: 1, TTL: 255
Internet Protocol Version 4, Src: 10.0.0.5, Dst: 10.1.1.1
Transmission Control Protocol, Src Port: 12345, Dst Port: 80
Data (20 bytes)
```

  
通过以上案例和实践，网络管理员可以更好地理解和应用 ACL，增强网络安全防护能力。  
  
  
