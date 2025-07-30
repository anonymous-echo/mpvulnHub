#  两个Google Vertex AI平台漏洞曝光：可能导致权限提升与敏感数据外泄   
 锋刃科技   2024-11-15 23:56  
  
![](https://mmbiz.qpic.cn/mmbiz_png/n5BstuRWwQpOrooaPFdgllBUY10cvJ8Cd7fN0sxGEKQeGUegyaunicTwrPKiaDaQ2wNuicIIoyZxbPq9wX0MrIYvg/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5EHHUdqrO47DbMXaFV69QMBm1OMXMf0x1Y8siaRdpIYlmLibD3rO8KoTlEIRMJb4DyQADFwdPTnNBSqtcfusbwwA/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/YhYicpKnr4247fYLPRKFM5O2ehNiaXplcqkc1b8UbFoH1Nj7Re4qruRGibicMHPiaas34s49luJsauRQyLzqp01AMBg/640?from=appmsg&wx_fmt=png "")  
  
近日，网络安全研究人员曝光了Google Vertex AI平台中的两个严重漏洞，如果被成功利用，攻击者可能通过这些漏洞提升权限并将存储在云端的机器学习模型（ML模型）和人工智能应用程序的数据外泄。  
  
通过这两个漏洞，攻击者能够绕过正常的安全机制，获取对Google云端资源的未授权访问，从而窃取敏感数据和专有的机器学习模型。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/KYJQTmhnOUQFIcaMibm31a2fDEicgAExkR9XfvtoHu923qZ97t8GEgrsb0UG2ID2BicCGEfC5TbrfUsu5F0icO6tBQ/640?from=appmsg&wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ub2EkGPegAd7PBd9icmO74MibKV7HrsHlLk3X0TZiaZzBQbuAGF81mYV3wepynDVbkevOtCdLzxpOP6icZ7f5rkwWg/640?from=appmsg&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/NLG0YnDqzvAmueyibjYktxGAPM4ibY3QLibgMOMRc1fM6DrsNh7ROIhfT4P8OFxic49oMva8YfjMGyibzZroGgdOfMw/640?from=appmsg&wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fWmp3zFswgHaymMEibnGLh6mqk9autBVEmDeUiaE4hiaAaOtZzgwibwq6fvGFuLvAThaZdtibCWqibVcznz0tbx7lYOQ/640?wx_fmt=png&from=appmsg "")  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/iboFNCcvWkSMg7Om2vzSseNXyc8iciaazL1VbMXhWibzKQIGIZibr6V3L9ON92kCDWlonOQzDaQvwqiaicfNlYOJXS7Tw/640?from=appmsg&wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/R2P71IIgt1BZtQBDTCPctNWjJX88AA5QMwSloc9ZfjI6HyKS3hzZNzibVQsI2x7sDqB72vTxTZmr8GjxgFR2JFA/640?from=appmsg&wx_fmt=gif "")  
  
Vertex AI平台概述  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WgWJib87LbAb2JudTQz9xeloxDUg0We6oXoNn5wO5xtZ53U0AwFWFibTZHBnNXDz1BmVLkkeeWkoc2nTMsXPKa8A/640?from=appmsg&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3pTKcXWlxyMrTAFPre3CGO1EQuiaFVF4F2ia8VognUCvcFTtnRaHeDPRxn91HM2CIQnyib4Jpb9d9oC0ZRJJ7V6Ug/640?wx_fmt=png "")  
  
Vertex AI是Google推出的一个全托管机器学习平台，旨在帮助开发者构建、训练、调优和部署机器学习模型。自2021年5月发布以来，它已经成为许多企业和开发者在AI应用领域的重要工具。Vertex AI利用多个功能模块（如Vertex AI Pipelines），使得用户能够自动化管理和监控机器学习的生命周期，从数据准备、模型训练到部署。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/fWmp3zFswgHaymMEibnGLh6mqk9autBVEbOGAN02XqJATfdWKdvuuQMBbe4BKDCRy6OIaBkjYtkPPn1icYteYic0Q/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iboFNCcvWkSMg7Om2vzSseNXyc8iciaazL1VbMXhWibzKQIGIZibr6V3L9ON92kCDWlonOQzDaQvwqiaicfNlYOJXS7Tw/640?from=appmsg&wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/R2P71IIgt1BZtQBDTCPctNWjJX88AA5QMwSloc9ZfjI6HyKS3hzZNzibVQsI2x7sDqB72vTxTZmr8GjxgFR2JFA/640?from=appmsg&wx_fmt=gif "")  
  
**漏洞详情：权限提升与模型外泄**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WgWJib87LbAb2JudTQz9xeloxDUg0We6oXoNn5wO5xtZ53U0AwFWFibTZHBnNXDz1BmVLkkeeWkoc2nTMsXPKa8A/640?from=appmsg&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3pTKcXWlxyMrTAFPre3CGO1EQuiaFVF4F2ia8VognUCvcFTtnRaHeDPRxn91HM2CIQnyib4Jpb9d9oC0ZRJJ7V6Ug/640?wx_fmt=png "")  
  
这两项安全漏洞的存在暴露了Vertex AI平台中存在的严重风险。如果这些漏洞被恶意攻击者利用，可能会导致数据泄露、资源滥用以及敏感模型的外泄。  
  
**1. 通过自定义作业进行权限提升**  
  
研究人员指出，Vertex AI Pipelines中的一个关键功能“自定义作业”是攻击者利用漏洞进行权限提升的突破口。自定义作业允许用户自动化模型训练流程，但这也给攻击者提供了滥用权限的机会。  
  
通过精心构造一个“恶意自定义作业”，攻击者可以在平台内注入一个“反向连接”的恶意镜像，从而获得回门访问权限。这使得攻击者能够绕过安全控制，获取对大量Google云服务资源的完全访问权限，包括列出服务帐户、管理存储桶、访问BigQuery表格等，这些资源可以被滥用来访问Google Cloud中的内部存储库，并下载敏感数据。  
  
**2. 恶意模型部署引发的敏感数据外泄**  
  
第二个漏洞则涉及到将“中毒的模型”部署到Vertex AI平台的租户项目中。当该恶意模型被部署到端点时，它会触发一个反向连接，利用“custom-online-prediction”服务帐户的只读权限，枚举Kubernetes集群并获取集群凭证，进而执行任意的kubectl命令。  
  
研究发现，这一过程能够帮助攻击者跨越Google Cloud Platform（GCP）与Kubernetes的边界，利用IAM工作负载身份联合（IAM Workload Identity Federation）获取GKE（Google Kubernetes Engine）集群中的敏感数据。通过进一步的横向移动，攻击者能够获取集群内新创建的镜像并提取其唯一标识符——镜像摘要，从而能够提取出这些镜像的内容。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iboFNCcvWkSMg7Om2vzSseNXyc8iciaazL1VbMXhWibzKQIGIZibr6V3L9ON92kCDWlonOQzDaQvwqiaicfNlYOJXS7Tw/640?from=appmsg&wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/R2P71IIgt1BZtQBDTCPctNWjJX88AA5QMwSloc9ZfjI6HyKS3hzZNzibVQsI2x7sDqB72vTxTZmr8GjxgFR2JFA/640?from=appmsg&wx_fmt=gif "")  
  
**模型外泄的严重后果**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WgWJib87LbAb2JudTQz9xeloxDUg0We6oXoNn5wO5xtZ53U0AwFWFibTZHBnNXDz1BmVLkkeeWkoc2nTMsXPKa8A/640?from=appmsg&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3pTKcXWlxyMrTAFPre3CGO1EQuiaFVF4F2ia8VognUCvcFTtnRaHeDPRxn91HM2CIQnyib4Jpb9d9oC0ZRJJ7V6Ug/640?wx_fmt=png "")  
  
更为严重的是，这些恶意模型不仅能够窃取机器学习模型，还能通过类似的方式窃取大语言模型（LLM）及其微调模型。开发者在不知情的情况下，如果将一个经过“木马”处理的模型上传到公共存储库并进行部署，攻击者就可以利用该漏洞窃取该平台上所有的ML模型及其微调数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iboFNCcvWkSMg7Om2vzSseNXyc8iciaazL1VbMXhWibzKQIGIZibr6V3L9ON92kCDWlonOQzDaQvwqiaicfNlYOJXS7Tw/640?from=appmsg&wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/R2P71IIgt1BZtQBDTCPctNWjJX88AA5QMwSloc9ZfjI6HyKS3hzZNzibVQsI2x7sDqB72vTxTZmr8GjxgFR2JFA/640?from=appmsg&wx_fmt=gif "")  
  
**漏洞的影响及修复**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WgWJib87LbAb2JudTQz9xeloxDUg0We6oXoNn5wO5xtZ53U0AwFWFibTZHBnNXDz1BmVLkkeeWkoc2nTMsXPKa8A/640?from=appmsg&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3pTKcXWlxyMrTAFPre3CGO1EQuiaFVF4F2ia8VognUCvcFTtnRaHeDPRxn91HM2CIQnyib4Jpb9d9oC0ZRJJ7V6Ug/640?wx_fmt=png "")  
  
这些漏洞的存在意味着，攻击者可以通过一个未经验证的模型就能在生产环境中进行攻击，最终导致敏感数据的泄露和模型的外泄。幸运的是，Google已经在负责任披露之后修复了这些漏洞，并加强了相关的安全防护措施。  
  
Google发言人表示：“我们已经采取了措施来解决这两个问题，并加强了Vertex AI平台的安全性。”但是，研究人员指出，这一事件提醒我们，随着人工智能技术的不断发展，如何有效保护AI环境的安全变得愈发重要。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iboFNCcvWkSMg7Om2vzSseNXyc8iciaazL1VbMXhWibzKQIGIZibr6V3L9ON92kCDWlonOQzDaQvwqiaicfNlYOJXS7Tw/640?from=appmsg&wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/R2P71IIgt1BZtQBDTCPctNWjJX88AA5QMwSloc9ZfjI6HyKS3hzZNzibVQsI2x7sDqB72vTxTZmr8GjxgFR2JFA/640?from=appmsg&wx_fmt=gif "")  
  
**安全建议：如何保护机器学习模型**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WgWJib87LbAb2JudTQz9xeloxDUg0We6oXoNn5wO5xtZ53U0AwFWFibTZHBnNXDz1BmVLkkeeWkoc2nTMsXPKa8A/640?from=appmsg&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3pTKcXWlxyMrTAFPre3CGO1EQuiaFVF4F2ia8VognUCvcFTtnRaHeDPRxn91HM2CIQnyib4Jpb9d9oC0ZRJJ7V6Ug/640?wx_fmt=png "")  
  
为了避免类似事件的发生，Palo Alto Networks的研究人员建议，组织应采取以下安全措施：  
- 严格控制模型部署：确保只有经过验证的模型可以被部署到生产环境，尤其是在公共存储库中上传的模型，必须经过严格审查。  
  
- 定期审计权限：组织应定期审计与模型部署相关的权限，确保自定义作业和服务帐户的权限不会被滥用。  
  
- 增强监控与检测：部署强有力的监控机制，及时发现可疑的活动并响应，特别是在模型部署和反向连接操作中。  
  
- 加强云环境与Kubernetes的安全隔离：确保GCP和Kubernetes之间的权限和安全边界得到有效隔离，避免攻击者通过横向移动扩大攻击面。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/iboFNCcvWkSMg7Om2vzSseNXyc8iciaazL1VbMXhWibzKQIGIZibr6V3L9ON92kCDWlonOQzDaQvwqiaicfNlYOJXS7Tw/640?from=appmsg&wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/R2P71IIgt1BZtQBDTCPctNWjJX88AA5QMwSloc9ZfjI6HyKS3hzZNzibVQsI2x7sDqB72vTxTZmr8GjxgFR2JFA/640?from=appmsg&wx_fmt=gif "")  
  
**结语**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WgWJib87LbAb2JudTQz9xeloxDUg0We6oXoNn5wO5xtZ53U0AwFWFibTZHBnNXDz1BmVLkkeeWkoc2nTMsXPKa8A/640?from=appmsg&wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/3pTKcXWlxyMrTAFPre3CGO1EQuiaFVF4F2ia8VognUCvcFTtnRaHeDPRxn91HM2CIQnyib4Jpb9d9oC0ZRJJ7V6Ug/640?wx_fmt=png "")  
  
此次曝光的Google Vertex AI漏洞为业界敲响了警钟：随着机器学习和人工智能技术的广泛应用，确保这些平台的安全至关重要。即便是看似小的漏洞，也可能导致敏感数据和知识产权的严重泄露。因此，开发者和企业必须加大对AI平台安全性的投入，严格审查和管理权限，确保AI模型的部署环境是安全的。  
  
随着AI技术日益成为企业的核心资产，如何平衡创新与安全，保护好这些创新成果，将成为未来AI行业面临的重要课题。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fWmp3zFswgEWAQw8ycXtibK1nNjQXv6hFZRiaXnbgPLZoWsIjfVOLCRAqxqBIfcLJ6gibBb5KaiaM9xoic4RaeOH0oA/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
