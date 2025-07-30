#  UbuntuServer24.04上使用NVIDIA GeForce RTX 4060Ti部署并训练DeepSeek R1大模型   
原创 SzHackingClub  灰帽安全   2025-01-30 17:20  
  
   用户想要在Ubuntu Server 24.04系统上，使用NVIDIA GeForce RTX 4060 Ti显卡本地部署DeepSeek R1大模型进行训练。我需要一步步帮他梳理可能的步骤，同时考虑可能遇到的问题和解决方案。  
  
   首先，确认系统要求和环境。Ubuntu Server 24.04应该是支持的，但需要安装合适的NVIDIA驱动。4060 Ti属于较新的显卡，可能需要较新的驱动版本，比如535或更高。用户需要从NVIDIA官网或者通过ppa源安装驱动，同时确保CUDA工具包兼容。  
  
   接下来是安装CUDA和cuDNN。DeepSeek R1可能依赖特定版本的CUDA，比如11.8或12.x，需要查看官方文档。安装完成后，需要设置环境变量，确保系统能找到CUDA路径。  
  
    然后是安装Python环境，推荐使用Anaconda或Miniconda创建虚拟环境，避免依赖冲突。Python版本可能需要3.8或3.9，具体看模型要求。接着用pip安装PyTorch，必须选择与CUDA版本对应的版本，例如torch 2.0+和CUDA 12.1。  
  
    接下来获取DeepSeek R1的源码，可能需要从GitHub克隆仓库，或者通过Hugging Face下载模型权重。需要注意模型是否开源，以及是否有访问权限。下载后，安装依赖库，如transformers、accelerate、deepspeed等，可能还需要特定版本的库，需要按照项目文档操作。  
  
    配置模型训练参数时，用户需要调整batch size、学习率等，以适应显存限制。4060 Ti的显存是16GB，可能无法支持太大的batch size，需要小心设置，或者使用梯度累积。同时，使用混合精度训练（FP16或BF16）可以节省显存，但需要确保硬件和软件支持。  
  
    可能遇到的问题包括显存不足，这时候需要考虑模型并行、数据并行，或者使用DeepSpeed的Zero优化阶段。另外，如果遇到CUDA版本不兼容，可能需要重新安装对应版本的PyTorch。还有，Ubuntu Server没有图形界面，所有操作需要通过命令行完成，用户需要熟悉相关命令。  
  
    另外，用户可能希望使用分布式训练加速，但单卡4060 Ti可能只能单卡训练。如果模型太大，无法载入显存，可能需要模型切分或者使用内存优化技术，如checkpointing。  
  
   最后，测试训练流程，运行示例脚本，观察日志和显存使用情况，确保没有错误。如果训练过程中出现错误，需要检查日志，排查依赖版本、路径设置等问题。  
  
  总结步骤大致是：安装驱动→CUDA→cuDNN→Python环境→PyTorch→下载模型和代码→安装依赖→配置参数→开始训练。需要用户仔细按照文档操作，并适时调整参数以适应硬件限制。  
  
在Ubuntu Server 24.04上使用NVIDIA GeForce RTX 4060 Ti部署并训练DeepSeek R1大模型，需按照以下步骤操作：  
  
1. 系统环境准备  
  
1.1 安装NVIDIA驱动  
```
# 添加官方驱动PPA
sudo add-apt-repository ppa:graphics-drivers/ppa
sudo apt update

# 查找推荐驱动版本（推荐选择535+版本）
ubuntu-drivers devices

# 安装驱动（例如535版本）
sudo apt install nvidia-driver-535

# 重启后验证
nvidia-smi
```  
  
1.2 安装CUDA Toolkit  
```
# 下载CUDA 12.2本地安装包（需从NVIDIA官网获取最新链接）
wget https://developer.download.nvidia.com/compute/cuda/12.2.2/local_installers/cuda_12.2.2_535.104.05_linux.run

# 安装CUDA
sudo sh cuda_12.2.2_535.104.05_linux.run

# 添加环境变量到~/.bashrc
echo 'export PATH=/usr/local/cuda/bin:$PATH' >> ~/.bashrc
echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> ~/.bashrc
source ~/.bashrc
```  
  
1.3 安装cuDNN  
  
从NVIDIA官网下载：https://developer.nvidia.com/cudnn  
  
与CUDA 12.x兼容的cuDNN版本。  
  
解压后复制文件到CUDA目录：  
```
sudo cp cudnn-linux-x86_64-8.9.7.29_cuda12-archive/include/cudnn*.h /usr/local/cuda/include/
sudo cp cudnn-linux-x86_64-8.9.7.29_cuda12-archive/lib/libcudnn* /usr/local/cuda/lib64/
sudo chmod a+r /usr/local/cuda/include/cudnn*.h /usr/local/cuda/lib64/libcudnn*
```  
  
2. Python环境配置  
  
2.1 安装Miniconda  
```
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh
bash Miniconda3-latest-Linux-x86_64.sh
# 按照提示完成安装后激活环境
source ~/.bashrc
```  
  
2.2 创建虚拟环境  
```
conda create -n deepseek python=3.10
conda activate deepseek
```  
  
2.3 安装PyTorch与依赖  
```
# 安装PyTorch（CUDA 12.1版本）
pip3 install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# 安装DeepSpeed（可选，用于分布式优化）
pip install deepspeed

# 安装其他依赖（根据DeepSeek R1要求）
pip install transformers datasets accelerate sentencepiece tensorboard
```  
  
  
3. 获取DeepSeek R1模型  
  
3.1 下载模型权重  
  
通过Hugging Face或官方渠道获取模型文件（需确认访问权限）：  
```
git lfs install
git clone https://huggingface.co/deepseek-ai/DeepSeek-R1
```  
  
3.2 下载训练代码  
```
git clone https://github.com/deepseek-ai/DeepSeek-R1-Training
cd DeepSeek-R1-Training
```  
  
4. 训练配置优化  
  
4.1 调整训练脚本  
  
修改训练脚本（如 train.py），关键参数示例：  
```
training_args = TrainingArguments(
    output_dir="./output",
    per_device_train_batch_size=4,  # 根据显存调整（4060 Ti约16GB）
    gradient_accumulation_steps=4,   # 累积梯度以模拟更大batch
    learning_rate=2e-5,
    fp16=True,                       # 启用混合精度训练
    logging_steps=100,
    max_steps=1000,
    deepspeed="ds_config.json"       # 使用DeepSpeed优化
)
```  
  
4.2 DeepSpeed配置（ds_config.json）  
```
{
  "fp16": {
    "enabled": true
  },
  "optimizer": {
    "type": "AdamW",
    "params": {
      "lr": "auto"
    }
  },
  "zero_optimization": {
    "stage": 2,
    "offload_optimizer": {
      "device": "cpu"
    }
  }
}
```  
  
5. 启动训练  
```
# 单卡训练命令
accelerate launch --num_processes 1 train.py

# 或使用DeepSpeed
deepspeed --num_gpus 1 train.py --deepspeed ds_config.json
```  
  
6. 显存优化技巧  
  
梯度检查点（Gradient Checkpointing）：在模型配置中启用：  
```
model.gradient_checkpointing_enable()
```  
  
Batch Size调整：从较小的值（如2）逐步测试，避免OOM。  
  
使用LoRA/QLoRA：若支持，可大幅降低显存占用。  
  
常见问题排查  
  
CUDA版本不匹配  
：  
1. 错误信息：CUDA error: no kernel image is available  
  
1. 解决：确保PyTorch的CUDA版本与系统安装一致（conda list | grep cuda  
）。  
  
1. **显存不足（OOM）**  
：  
  
1. 降低per_device_train_batch_size  
，增加gradient_accumulation_steps  
。  
  
1. **依赖冲突**  
：  
  
1. 使用pip freeze > requirements.txt  
导出环境，确保与官方推荐版本一致。  
  
通过以上步骤，您应能在RTX 4060 Ti上顺利启动DeepSeek R1的训练任务。建议从较小规模的数据集开始测试，逐步调整超参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1bQDlhHMib4AoxN1uN9D9c1ibdnPviaOD2v7hKY8FBZBx4c0UcuOhGfEI5OibJwQtvSLxHsDWbTib5pSeic0hSOicJwYw/640?wx_fmt=png "")  
  
  
