#  Gnu Glibc 逻辑缺陷漏洞   
 上汽集团网络安全应急响应中心   2025-05-20 15:55  
  
漏洞情报  
  
  
  
  
  
**Gnu Glibc 逻辑缺陷漏洞**  
  
  
**【 漏洞编号 】**  
  
CVE-2025-4802  
  
  
**【 情报等级 】**  
  
**高危**  
  
  
**【 漏洞描述 】**  
  
360漏洞云监测到GNU C 库版本 2.27 到 2.38 中被披露存在逻辑缺陷漏洞，这一漏洞使得攻击者能够在调用 dlopen 的静态编译且设置了 setuid 的二进制文件中控制动态共享库的加载。攻击者根据自己的意图加载动态共享库，从而可能进行恶意操作，比如执行恶意代码等。官方已经在新版本中修复此漏洞，建议受影响用户及时升级到安全版本。  
  
  
**【 影响产品 】**  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="99.0000%" width="99.0000%" style="border-width: 1px;border-color: rgb(255, 255, 255);border-style: solid;background-color: rgb(231, 231, 231);padding: 6px;box-sizing: border-box;"><section style="text-align: center;font-size: 14px;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><span leaf="">GNU C Library,glibc,Glibc&gt;=2.27&amp;&amp;&lt;=2.38</span></p></section></td></tr></tbody></table>  
  
**【 解决方案与修复建议 】**  
  
1.修复步骤  
  
升级GNU C库到2.39或更高版本。可以通过以下步骤完成：  
  
- 对于基于Debian的系统，运行以下命令：  sudo apt-get update  
  
  sudo apt-get upgrade  
  
- 对于基于Red Hat的系统，运行以下命令：  sudo yum update  
  
  sudo yum upgrade  
  
- 对于其他Linux发行版，请参考相应的包管理器文档进行更新。  
  
- 官方产品补丁链接：https://www.gnu.org/software/libc/  
  
