#  Wazuh监视恶意命令执行   
原创 网络安全菜鸟  安全孺子牛   2025-04-28 00:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2gG5sygYR7bVZDaVan99kMcwYk4Uekeobq5KDctHbYAJBrqXBkeGt42QiaSzMPicVg3CQClo7RetH8O4xLe5nZZw/640?wx_fmt=gif&from=appmsg "")  
  
**点击蓝字，关注我**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2gG5sygYR7bVZDaVan99kMcwYk4UekeoSE1olhebdSOyQ4ic7sokon4xFrXYzh42EYYCvgfQWvdSAjOT7jCnoxQ/640?wx_fmt=gif&from=appmsg "")  
  
  
1.简介  
  
### 1.1 功能简介  
  
Auditd 是 Linux 系统原生的审计实用程序。它用于 Linux 终结点中的记账操作和更改。  
  
在 Ubuntu 端点上配置 Auditd，以考虑给定用户执行的所有命令。这包括用户在模式下或更改为 root 用户后运行的命令。您可以配置自定义 Wazuh 规则以对可疑命令发出警报。  
### 1.2 测试环境  
<table><tbody><tr style="height: 33px;"><td style="border: 1px solid #d9d9d9;background-color: #499cfe;"><p style="text-align:center;margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: #2a2d34;"><span leaf="">端点</span></span></strong></p></td><td style="border: 1px solid #d9d9d9;background-color: #499cfe;"><p style="text-align:center;margin: 0;padding: 0;min-height: 24px;"><strong><span style="color: #2a2d34;"><span leaf="">描述</span></span></strong></p></td></tr><tr style="height: 33px;"><td style="border: 1px solid #d9d9d9;background-color: #28282a;"><p style="text-align:center;margin: 0;padding: 0;min-height: 24px;"><span style="color: #ffffff;font-size: 13px;"><span leaf="">Ubuntu 22.04</span></span></p></td><td style="border: 1px solid #d9d9d9;background-color: #28282a;"><p style="text-align:left;margin: 0;padding: 0;min-height: 24px;"><span style="color: #ffffff;font-size: 13px;"><span leaf="">配置 Auditd 以监视恶意命令的执行。然后，利用 Wazuh CDB 列表查找功能创建可在其上运行的潜在恶意命令列表。</span></span></p></td></tr></tbody></table>## 2.Linux环境配置  
### 2.1Ubuntu配置  
#### 1）安装并启用audit  
```
sudo apt -y install auditd
sudo systemctl start auditd
sudo systemctl enable auditd
```  
#### 2）添加审核规则  
```
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b32 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
echo "-a exit,always -F auid=1000 -F egid!=994 -F auid!=-1 -F arch=b64 -S execve -k audit-wazuh-c" >> /etc/audit/audit.rules
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeocXK6YZGEfD7lfdootqiazSkBwJLZgTzib2rhlSQ5Z8jm4HggHezIN4hw/640?wx_fmt=png&from=appmsg "")  
#### 3）重新加载规则  
```
sudo auditctl -R /etc/audit/audit.rules
sudo auditctl -l
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeocibmPibec8QScp9TCicLenBmjxk95zkyI9e7d20HeeR0Rbx4SLUPdQwJQ/640?wx_fmt=png&from=appmsg "")  
#### 4）配置audit日志读取  
  
配置Wazuh代理文件，允许Wazuh代理读取auditd日志文件  
```
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```  
#### 5）重启代理服务  
```
sudo systemctl restart wazuh-agent
```  
### 2.2Wazuh服务器配置  
#### 1）查看配置的查找文件中的键值对  
```
cat /var/ossec/etc/lists/audit-keys
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeoTluG5IAO7H0A50WKHZv7biaQnB8l5jsL7ib8ic4V4ZSuUxaia8BNPRD5HA/640?wx_fmt=png&from=appmsg "")  
#### 2）创建CDB列表  
```
ncat:yellow
nc:red
tcpdump:orange
```  
  
修改文件权限  
```
chown wazuh:wazuh /var/ossec/etc/lists/suspicious-programs
chmod 660 /var/ossec/etc/lists/suspicious-programs
```  
#### 3）添加CDB列表到配置文件中  
```
<list>etc/lists/suspicious-programs</list>
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeobTufTCpnH9XicLtoE3p6x18PQbVevoiaibGTicY4LGt2YTHrYMJT66m72Q/640?wx_fmt=png&from=appmsg "")  
#### 4）创建高危规则  
  
创建一个高严重性规则，以便在执行“红色”程序时触发  
```
<group name="audit">
  <rule id="100210" level="12">
      <if_sid>80792</if_sid>
  <list field="audit.command" lookup="match_key_value" check_value="red">etc/lists/suspicious-programs</list>
    <description>Audit: Highly Suspicious Command executed: $(audit.exe)</description>
      <group>audit_command,</group>
  </rule>
</group>
```  
#### 5）重启wazuh服务  
```
sudo systemctl restart wazuh-manager
```  
### 2.3攻击测试  
#### 1）安装NC  
```
sudo apt -y install netcat
nc -v
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeolhEH3hia6A053vnG41jVJejKkvEXYBoA7vkicu205KgvichSmZibIKR6sA/640?wx_fmt=png&from=appmsg "")  
### 2.4告警查看  
#### 1）查看audit日志  
```
more /var/log/audit/audit.log | grep nc
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeocV0QDw6vOjzHOvyemL1TsshtyCNtyhtH2IhcP4yp6c1er3uB3ibMsFQ/640?wx_fmt=png&from=appmsg "")  
#### 2）查看告警  
  
查询语句：data.audit.command:nc  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeoOp6ukA2JMHbmelZKDW9Yk8Fiad7rBpRsv5guibibKd1u3IeuXXQMVQ3RQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeoGicUib2oHNCRFVokpJ7uUblbZLHW2RHXWVnanCWGRukJRhoSKpM9AVUg/640?wx_fmt=png&from=appmsg "")  
  
**END**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2gG5sygYR7bVZDaVan99kMcwYk4UekeoB8v0hBicgpmtibl3Zjkiau8XHiagLueptrBMPBkAOLvrxloAMo2bELCZqg/640?wx_fmt=png&from=appmsg "undefined")  
  
**信息安全**  
  
  
关注小助理微信  
  
一起入群成长交流  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2gG5sygYR7bVZDaVan99kMcwYk4UekeoygTNUEbwLlXibrJiaiaRCwAvW7V7hGTRoibjRsdw17qa1zKHha8ibh3ZADg/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
