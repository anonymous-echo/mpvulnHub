#  Grafana 已全面支持 VictoriaMetrics 体系   
原创 小斐Lab  网络小斐   2025-02-06 08:28  
  
**大家好，我是小斐呀。**  
  
关于监控告警这块的我之前几乎都是推荐使用 **VictoriaMetrics**  
 时序数据库，但是在 **Grafana**  
 下使用 **VictoriaMetrics**  
 时序库的时候需要单独安装 **VictoriaMetrics**  
 数据源插件，要么使用 **VictoriaMetrics**  
 时序库然后 **Grafana**  
 下使用 **Prometheus**  
 数据源，但是那样不就不能直接在 **Grafana**  
 中使用 **VictoriaMetrics**  
 的某些高级功能嘛。  
  
之前星球教程里面都是手动下载 **VictoriaMetrics**  
 数据源插件压缩包，然后解压到 **Grafana**  
 下的插件目录中，默认为 **/var/lib/grafana/plugins**  
 目录下实现在 **Grafana**  
 下使用 **VictoriaMetrics**  
 数据源，安装完成后在 **Grafana**  
 中是这样子的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JLmMWSico1gwO8YXUvwGxqyAqiaxmI2wWl3yv5ftr4gfbWtZV1kjZjEwVaqlDkMia6O54b4UibDeZIQAFmLvLtvWGw/640?wx_fmt=png&from=appmsg "")  
  
可以看到是未签名的插件，而且安装步骤有些复杂，如下是之前的安装步骤：  
```
# 安装 victoriametrics-datasource
# 获取最新版本插件
latest_version=$(curl -s https://api.github.com/repos/VictoriaMetrics/victoriametrics-datasource/releases/latest | grep -oP '"tag_name": "\K(.*)(?=")')
# 下载安装
grafana-cli --pluginUrl https://github.com/VictoriaMetrics/victoriametrics-datasource/releases/download/${latest_version}/victoriametrics-datasource-${latest_version}.zip plugins install victoriametrics-datasource

# 修改 grafana.ini 配置 允许加载未签名的插件
[plugins]
allow_loading_unsigned_plugins = victoriametrics-datasource

# 备份原配置为grafana.ini.bak
sudo cp /etc/grafana/grafana.ini /etc/grafana/grafana.ini.bak
# 使用sed替换
sudo sed -i '/^\[plugins\]/,/^\[/{s/;allow_loading_unsigned_plugins =/allow_loading_unsigned_plugins = victoriametrics-datasource/}' /etc/grafana/grafana.ini

# 重启 Grafana
sudo systemctl restart grafana-server.service

```  
  
就这么简单的步骤还是有很多小伙伴出现各种问题，最多的就是网络问题导致下载插件特别慢，没办法只能浏览器下载解压安装实现。  
## 版本升级  
  
**VictoriaMetrics**  
 数据源插件之前在 **v0.12.0**  
 之前版本的插件ID为 **victoriametrics-datasource**  
 。  
  
从 **v0.12.0**  
 及之后的版本新的插件 ID 为 **victoriametrics-metrics-datasource**  
 ，从此版本后 **Grafana**  
 将把此视为新插件，这是重大更新。  
  
从 **v0.13.0**  
 开始 **Grafana**  
 开始正式支持 **VictoriaMetrics**  
 数据源插件和 **VictoriaLogs**  
 数据源插件。  
  
之前修改过 **Grafana**  
 的配置文件 **/etc/grafana/grafana.ini**  
 配置文件的配置，允许为签名插件加载运行，如下所示：  
```
allow_loading_unsigned_plugins = victoriametrics-metrics-datasource
allow_loading_unsigned_plugins = victoriametrics-datasource

```  
  
现在我们更新后，可直接注释配置即可。  
  
现在我们可以直接在 **Grafana**  
 中安装安装使用 **VictoriaMetrics**  
 数据源插件和 **VictoriaLogs**  
 数据源插件，如下所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JLmMWSico1gwO8YXUvwGxqyAqiaxmI2wWl4rzLoIyvWgYgrNXvBBNbOgqSYA32dEw147phaverSUklAK4iaM1kbMQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JLmMWSico1gwO8YXUvwGxqyAqiaxmI2wWlaTUsaMtOIib00QcxGFqbrQDicyX3kk5gE4gwzZo8uaIWyfTtiap45KBDw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JLmMWSico1gwO8YXUvwGxqyAqiaxmI2wWllh1kOV2DAgC21srxkKiapPEheZW8WibnTg6X2O7ib6ILutDAdYMTaLthg/640?wx_fmt=png&from=appmsg "")  
  
果然 **Grafana**  
 还是非常的可以，很积极快速的支持 **VictoriaMetrics**  
 全套体系。  
  
本地化安装的 **Grafana**  
 可直接执行命令安装：  
```
# 安装 VictoriaMetrics 数据源插件
grafana-cli plugins install victoriametrics-metrics-datasource
# 安装 VictoriaLogs 数据源插件
grafana-cli plugins install victoriametrics-logs-datasource
# 更新所有插件
grafana cli plugins update-all

```  
  
这里我是使用了 **Grafana**  
 较新版本，建议更新 **Grafana**  
 大版本，如 **10**  
 和 **11**  
 的最新子版本，老版本可能没有支持。  
## 添加数据源  
  
打开 **Grafana**  
 添加数据源：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JLmMWSico1gwO8YXUvwGxqyAqiaxmI2wWldqgLxnqIyNicqP9TYJdEHtRQ7dsv9SQdtEfxiaLElLAOqyJ7sJ24icibkw/640?wx_fmt=png&from=appmsg "")  
  
  
  
