> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484942&idx=1&sn=baf5d858e68af91f045b6c4cc52c65b5

#  Linux单服务器漏洞处置SOP框架——最小化应用系统运行环境安全风险  
原创 Richard  方桥安全漏洞防治中心   2025-07-08 10:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2JVOUiaJORTsQZUdMXdStiate08bbYkYJ2zISwoMDG2yMURyiaM0GRk17UutX8RiaSEibwicOwR4I3GmdT8fpgrbgGFA/640?wx_fmt=png&from=appmsg "")  
  
本SOP 旨在提供一个详细、可执行的指南，用于修补单台 Linux 服务器上包括操作系统（CentOS 8）、数据库（MySQL/MariaDB）、Tomcat 和Redis的已知漏洞。  
  
# 【目标】  
  
有效识别并修补单台 Linux 服务器上的所有已知软件漏洞，最小化业务中断风险，并确保系统稳定运行。  
  
# 【特别说明】  
  
本SOP 不包括   
修补Web应用程序本身可能存在的漏洞。  
  
# 【关联文件不完全清单】  
  
《Linux最小化安装（CentOS 8分册）》  
  
《Linux安全配置基线（CentOS 8分册）》  
  
《Linux升级、打补丁、修改配置的原则和要求（CentOS 8分册）》  
  
《服务器操作系统安全管理要求（CentOS 8分册）》  
  
《单个软件产品安全SOP（Apache Tomcat）》  
  
《单个软件产品安全SOP（MySQL/MariaDB）》  
  
《单个软件产品安全SOP（Redis）》  
  
……  
  
# 【前提条件】  
- 已获取服务器的 root 或 sudo 权限。  
  
- 服务器能够访问互联网以进行软件包更新（如 yum 或 dnf 源）。  
  
- 已准备好必要的备份工具和存储空间。  
  
- 已与业务方沟通并获得维护窗口  
（务必避开业务高峰期）  
。  
  
- 了解服务器上运行的具体软件版本和配置。  
  
# 【具体流程与步骤】  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2JVOUiaJORTsQZUdMXdStiate08bbYkYJ2hKftvVjF6c6fn6tKk5GgMs4z0FqaDykroZCbPsicVY2m66qQm1Ulmmw/640?wx_fmt=png&from=appmsg "")  
## 1.准备与风险评估  
  
**1.1 确认服务器信息**  
- **操作系统版本：**  
 确  
认是 CentOS 8。  
  
- **核心服务清单：**  
 列出所有运行的服务（例如：Apache Tomcat, MySQL/MariaDB, Redis等）。  
  
- **应用程序清单：**  
 识别部署的 Web 应用程序和它们的依赖。  
  
- **网络连通性：**  
 确认服务器可以访问软件包仓库和外部网络。  
  
**1.2 评估当前漏洞状态**  
- **系统级漏洞扫描：**  
   
运行dnf updateinfo list security all (CentOS 8) 来查看所有可用的安全更新。  
  
- **中间件漏洞扫描：**  
MySQL/MariaDB、Redis、Tomcat等，检查其官方安全公告，或使用专业漏洞扫描工具检测这些服务可能存在的漏洞。  
  
- **Java Web应用：**  
 使用 **OWASP Dependency-Check**  
   
或其它 SBOM (软件物料清单) 工具扫描 Web 应用的依赖库，识别其使用的组件可能存在的已知漏洞。  
  
- **手动排查：**  
针对监管部门或者上级单位通报的关键服务（如 Log4j、Spring Framework等）已知高危漏洞、高危端口、弱口令等，确保响应通报范围内的所有高风险因素。  
  
**1.3 制定回退计划**  
- **系统快照：**  
 如果服务器是虚拟机，务必在操作前创建虚拟机快照。  
  
- **数据备份******  
  
**数据库：**  
 使用 mysqldump 对 MySQL/MariaDB 数据库进行逻辑备份，并确保备份文件已传输到安全位置。****  
  
**配置文件：**  
 备份所有可能被修改的配置文件，例如 /etc 下的服务配置、Tomcat 的 conf 目录、Web 应用部署目录（webapps）、数据库配置文件 my.cnf、Redis 配置文件 redis.conf 等。（命令示例：sudo cp /path/to/config_file /path/to/config_file.bak）  
  
- **服务启停脚本：**  
编写/检查各个服务的停止和启动命令，备用。  
  
**1.4 通知与协调**  
- 与业务方确认维护窗口，并预估可能的业务中断时间。  
  
- 通知开发、测试、运维团队，确保他们知晓本次操作。  
  
## 2.系统与基础软件漏洞修补  
  
**2.1 系统及软件包更新**  
- **执行安全更新：**  
 使用包管理器更新所有系统包到最新版本，优先考虑安全补丁。****  
  
**CentOS 8：**  
   
  
sudo dnf update   
--security -y  
  
- **内核更新：**  
 如果内核有安全更新，系统可能会要求重启。请在后续“验证与重启”阶段进行。  
  
**2.2 数据库软件修补 (MySQL/MariaDB)**  
- **停止数据库服务：**  
  
sudo systemctl stop mysqld # MySQL  
  
或  
  
sudo systemctl stop mariadb # MariaDB  
  
- **执行更新：**  
  
通常数据库版本更新会通过系统包管理器提供，确保在系统更新时已包含。如果需要手动更新到特定版本以修补漏洞，请按照数据库官方文档的指引进行。参考《单个软件产品安全SOP（MySQL/MariaDB）》****  
  
**命令示例**  
  
sudo dnf   
update  
 mysql  
-  
server   
-  
y  
  
或  
  
sudo dnf   
update  
 mariadb  
-  
server   
-  
y  
  
- **启动数据库服务：**  
  
sudo systemctl   
start  
 mysqld  
  
或  
  
sudo systemctl   
start  
 mariadb  
  
- **执行 mysql_upgrade (如果适用)：**  
 数据库更新后，运行此命令检查并升级兼容性。****  
  
**命令示例**  
  
sudo my  
sq  
l_upgrade -u root -p   
#输入数据库root密码  
  
**2.3 其它基础软件修补 (以Redis为例)**  
- **停止服务：**  
  
sudo   
systemctl stop redis  
  
- **执行更新：**  
通过dnf更新相应软件包。  
  
命令示例  
  
sudo dnf update redis -y  
  
- **启动服务：**  
  
sudo systemctl start redis  
  
## 3.应用中间件（Tomcat）漏洞修补  
  
**3.1 停止 Tomcat 服务**  
- **命令示例：**  
   
  
sudo systemctl stop tomcat  
  
或  
  
s  
udo  
 sh   
/path/  
to  
/tomcat/  
bin  
/  
shutdown.s  
h  
  
**3.2 Tomcat 容器本身漏洞修补**  
- **升级 Tomcat 版本：**  
   
如果是 Tomcat 容器本身存在漏洞，最直接的方法是升级到已修复漏洞的最新稳定版本。****  
  
**步骤：**  
参考《单个软件产品安全SOP（Apache Tomcat）》。****  
  
**注意：**  
 此步骤可能需要较长时间，并可能引入兼容性问题，务必谨慎。  
  
**3.4 启动 Tomcat 服务**  
- **命令示例：**  
  
sudo systemctl start tomcat  
  
或   
  
sudo sh   
/path/  
to  
/tomcat/  
bin  
/  
startup.sh  
  
## 4.验证与重启  
  
**4.1 服务状态检查**  
- 确认所有服务  
（SSH, MySQL/MariaDB, Tomcat, Redis 等）均已成功启动并运行正常。（**命令示例：**  
 sudo systemctl status <service_name>）  
  
**4.2 应用功能验证**  
- 访问 Web 应用程序，进行基本功能测试，确保核心业务流程正常。  
  
- **连接**  
数据  
库和 Redis，执行简单查询，确保数据读写正常。  
  
**4.3 日志检查**  
- **检查**  
 /var/log/messages、/var/log/secure、Tomcat 日志（catalina.out）、数据库日志、Redis 日志等，确认没有新的错误或异常信息。  
  
**4.4 重启系统 (如果必要)**  
- 如果更新了内核或其它关键组件，或者为了确保所有更改生效，建议重启系统。****  
  
**命令示例：**  
  
sudo reboot  
  
- **重启后再次验证：**  
系统重启后，再次执行上述 4.1-4.3 步骤，确认所有服务和应用均能正常自启动并提供服务。  
  
## 5.清理与报告  
  
**5.1 清理临时文件**  
- 删除本次修补过程中产生的临时文件、备份的旧版本安装包等。****  
  
**命令示例：**  
  
sudo rm -rf /tmp/*  
   
 #谨慎执行，或指定清理目录  
  
**5.2 更新文档**  
- **更新**  
服务器配置文档，记录修补日期、修补内容（更新了哪些包、版本号）、遇到的问题及解决方案。  
  
**5.3 撰写处置报告**  
- 向**管理层和相关团队**  
提交一份处置报告，说明已修复的漏洞、修补过程、验证结果以及潜在的风险提示。  
  
**5.4 后续监控**  
- 在接下来几天，更密切的监控服务器，特别是性能和日志，保障稳定运行。  
  
- 定期扫描漏洞，确保及时发现新漏洞，及时修补，持续保障安全。  
  
# 【注意事项与建议】  
- **隔离环境测试：**  
在生产服务器上执行前，务必在与生产环境一致的测试环境中充分测试和验证。  
  
- **最小权限原则：**  
在执行任何操作时尽量使用最小权限账户，避免无差别地使用root用户。  
  
- **分批次执行：**  
如有多台服务器，可以考虑分批修补，降低整体风险。  
  
- **Ansible自动化：**  
对于批量修补，强烈建议将本SOP中列出的流程和步骤转化为 Ansible Playbook，保证标准化、实现自动化和幂等性。这样不仅能节省时间，还能减少人为错误。  
  
- **版本兼容性：**  
升级软件时，务必注意新版本与现有应用程序和操作系统的兼容性。  
  
- **最小化服务中断及其影响：**  
   
尽量选择在业务波谷期（务必避开业务高峰期）执行变更活动，并将可能出现的服务中断提前通知所有相关方。  
  
本SOP提供了一个框架作为参考。在实际操作中需要根据服务器的具体配置、应用程序的复杂性以及所在单位的安全策略适当调整。  
  
# 【注释】  
  
注1：**“幂等性”（Idempotence）**  
   
是指一个操作或指令在执行一次或多次后，**系统状态保持不变，或者产生相同的结果，不会因为重复执行而带来额外或不期望的副作用。**  
  
简单来说，就是：**“重复执行，结果不变。”**  
  
比如说有一个按钮，  
- **非幂等操作的例子：**  
   
一个“提交订单”的按钮。点击一次，生成一个订单。再点击一次，又生成一个新订单。每次点击都会产生新的、不一样的结果。  
  
- **幂等操作的例子：**  
   
一个“开灯”的按钮。点击一次，灯亮了。再点击一百次，灯依然是亮的，不会变得更亮，也不会因为多按了几次就爆炸或出现其它问题。  
  
在 Ansible Playbook 的语  
境中，幂等性至关重要：  
- **避免重复操作的副作用：**  
 比如，某个Playbook中有一个任务是“创建用户”。如果这个任务是幂等的，那么当第一次运行它时，创建了指定的用户。当第二次、第三次甚至更多次运行这个 Playbook 时，如果该用户已经存在，这个任务会检测到并且不会再创建，从而避免报错或产生多余的用户。  
  
- **确保系统状态一致：**  
 无论Playbook运行多少次，它都会将目标服务器配置成期望的最终状态。  
  
- **简化故障恢复：**  
 如果Playbook在中间某个步骤失败了，你直接重新运行整个Playbook。幂等性保证了已经成功的部分不会被破坏或重复配置，而失败的部分会从上次中断的地方继续执行，直到所有任务都成功完成。  
  
- **提高可靠性：**  
   
运维人员可以放心地反复运行Playbook，而不用担心会破坏已有的配置或引入新的问题。这对于“批量修补”尤其重要，因为可能需要对大量服务器进行相同的操作，或者在不确定哪些服务器已经应用了补丁时，可以安全地再次运行。  
  
本文档中提到“将上述步骤转化为Ansible Playbook，实现自动化、标准化和**幂等性**  
”  
时，这表明编写的Ansible任务会检查当前服务器的状态，如果已经达到了目标状态，就不再执行任何操作；如果还没有达到，它就会执行必要的操作来使服务  
器  
达  
到目标状态，并且无论执行多少次，最终结果都是一样的，不会有意外发生。  
  
  
  
- End -  
  
  
  
推荐阅读  
  
[初识安全漏洞防治SOP](https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484912&idx=1&sn=231332522ccc8edc4d7cd46df1c75b8c&scene=21#wechat_redirect)  
  
  
[单漏洞SOP（Log4j漏洞排查、评估、处置、验证）](https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484920&idx=1&sn=ce8fd61451fd89fb8aae0451e460d9f1&scene=21#wechat_redirect)  
  
  
[单个软件产品SOP——保持关键软件（Tomcat）无懈可击](https://mp.weixin.qq.com/s?__biz=Mzk0OTQzMDI4Mg==&mid=2247484929&idx=1&sn=2f15f03c8d8606163c5e94fabe4df3ea&scene=21#wechat_redirect)  
  
  
  
  
