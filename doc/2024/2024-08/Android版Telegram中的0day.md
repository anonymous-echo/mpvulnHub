#  Android版Telegram中的0day   
cc  信安百科   2024-08-03 22:04  
  
Android版Telegram中的EvilVideo漏洞可让攻击者发送伪装成视频的恶意软件。ESET发现了这个零日漏洞，促使Telegram在10.14.5版本中发布了安全补丁。立即更新！  
  
  
ESET网络安全研究人员发现了一个针对Android版Telegram的零日漏洞，被称为“EvilVideo”，该漏洞于2024年6月6日在俄罗斯地下论坛XSS.IS上出售。此漏洞允许攻击者通过Telegram频道、群组和聊天分发伪装成视频文件的恶意Android负载。  
  
该漏洞的发现促使ESET进行了彻底的分析，并于2024年6月26日向Telegram提交了一份详细的报告。然而，该漏洞的详细信息直到2024年7月22日才公布。  
  
据报道，Telegram对ESET的披露做出了及时回应，并于2024年7月11日发布了更新，修补了10.14.5及以上版本中的漏洞。  
  
ESET发现EvilVideo漏洞正在地下论坛上宣传，卖家在公共Telegram频道中提供了截图和演示漏洞的视频。这些信息使ESET能够追踪该频道并获取有效载荷以进行进一步测试。  
  
分析显示，该漏洞影响Telegram 10.14.4及更早版本。该负载可能使用Telegram API制作，伪装成多媒体文件。在聊天中共享时，恶意负载会显示为30秒的视频。默认情况下，Telegram会自动下载媒体文件，这意味着启用此设置的用户在打开对话时会自动下载恶意负载。  
  
如果用户尝试播放“视频”，Telegram会显示一条错误消息，提示使用外部播放器。点击此消息中的“打开”按钮会提示安装伪装成外部播放器的恶意应用程序。然后，Telegram会要求用户启用未知应用程序的安装，从而导致恶意应用程序的安装。  
  
  
  
  
  
ESET在其他Telegram客户端（包括Telegram Web和适用于Windows的Telegram Desktop）上测试了该漏洞，发现漏洞在这些平台上不起作用。两个客户端都显示错误消息并将有效负载视为多媒体文件，从而阻止漏洞执行。  
  
EvilVideo背后的威胁者还提供了Android加密器即服务，声称它是完全不可检测的(FUD)。自2024年1月11日起，该服务就在同一地下论坛上宣传。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Whm7t4Je6uoiaic1MdgGkD2XS0xZzELUJE5m9fyXChSQL8nDWqVQMnIuGkFzeLLCv4rWdOghzlice0QEbpOnhMx0g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
ESET于2024年6月26日向Telegram报告了EvilVideo漏洞，并在未收到初步回复后于2024年7月4日再次报告。Telegram确认他们正在调查此问题，并于2024年7月11日发布了补丁，版本为10.14.5。该补丁可确保共享文件被正确识别为应用程序而不是视频。  
  
ESET发现EvilVideo漏洞表明，完全的安全是不可能的，即使是流行的消息平台也容易受到零日漏洞的攻击。然而，由于ESET及时介入和Telegram快速响应，该漏洞已被修补。Android上的Telegram用户应将其应用程序更新到最新版本，以防范EvilVideo和类似威胁。  
  
—— —— 来源于网络  
   
        
  
  
