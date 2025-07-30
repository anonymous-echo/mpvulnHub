#  Discord爆"幽灵"漏洞存在隐私泄漏风险   
原创 一个不正经的黑客  一个不正经的黑客   2024-12-25 14:22  
  
# Discord爆"幽灵"漏洞存在隐私泄漏风险  
## 漏洞详情   
  
Discord 有一个名为“邀请为访客”的功能，适用于语音频道。  
  
当你使用这个功能时，它会生成一个邀请链接，当有人通过该邀请链接加入时，他们会进入语音频道。  
  
如果他们离开语音频道，他们将被踢出服务器，这就是为什么它被称为访客的原因。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMpVjoBo0ciagyrR4uXmSJ8G0Emnlia6Od6aUsSlia5ZDMvRFpSdUUab9KKUFdCaHuLkgicVGzdichSD1bw/640?wx_fmt=png&from=appmsg "")  
  
我想，如果在更换语音频道时进行限速，然后以访客身份加入服务器会发生什么？  
  
我尝试了这个方法，当我加入服务器时，我没有进入语音频道，我感到很惊讶。  
  
我本应该在语音频道中，这样如果我离开语音频道，我就会被踢出语音频道，但我不能离开语音频道，因为我根本不在语音频道中，所以我永远待在服务器中，而没人知道我在服务器里，因为在成员列表中看不到我。  
  
而且，我不能被禁用，因为它认为我不在服务器中，所以我实际上是一个“幽灵”，可以悄悄读取消息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMpVjoBo0ciagyrR4uXmSJ8G0gphkeia2j9pdgJh7EDj6jwG59UzOe1rKicSspywxhvjWOmJNF0rOYzoQ/640?wx_fmt=png&from=appmsg "")  
  
发现这个漏洞后，我通过 HackerOne 向 Discord 的安全团队报告了此问题，并获得了$$$金额的奖励。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMpVjoBo0ciagyrR4uXmSJ8G0lmicic4dliaD3TtbIWKtg5GGnD2V7SoicXfibiaRkgaxqB8pO4rliaOp6X1Sg/640?wx_fmt=png&from=appmsg "")  
## 漏洞点评   
  
漏洞的核心问题在于，Discord 的“邀请为访客”功能和语音频道的管理机制在某些情况下没有正确处理用户的状态（  
分步骤，黑客破坏中间过程，导致系统出现异常造成安全问题）。  
  
特别是当用户通过限速等手段阻止自己进入语音频道时，系统无法识别出他们的存在，从而使得这些用户可以以“幽灵”身份悄悄留在服务器中，读取消息而不被发现。  
  
thanks for: https://mirzebaba.medium.com/how-i-discovered-a-high-severity-vulnerability-to-secretly-read-messages-on-discord-36325b1cf72b  
  
  
  
  
