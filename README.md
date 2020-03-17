该项目在 https://github.com/feixuelove1009/CMDB 的基础上进行开发

版本更新：

- 20191206 AssetManage-v1.0.0
  - 整合多个云上的资产信息
  - 可视化展示
  - 通过excel文件导入资产信息
  - 将nmap扫描后生成的xml文件导入，生成端口信息
- 20200113 AssetManage-v2.0.0
  - 增加基线检查的后端可视化展示界面
- 20200317 AssetManage-v3.0.0
  - 增加基于agent的主机漏洞扫描功能
  - 增加服务器端口开放扫描功能

功能：

- 整合多个云上的资产信息
- 可视化展示
- 通过excel文件导入资产信息
- masscan+nmap快速扫描服务器开放的端口信息
- 基于agent的主机漏洞扫描功能
- 基于agent的基线检查功能

使用步骤：

```python
安装最新版sqlite3
python -m pip install requirements.txt
git clone https://github.com/chroblert/AssetManage.git
进入assetMange-master目录
python manage.py makemigrations
python manage.py migrate
python manage.py runserver <ip>:<port>
# 资产管理功能
点击上传文件，选择上传相应的文件
# 安全基线检查结果展示界面
点击基线检查
```

效果图：

![1575599919603](README/1575599919603.png)

![1575599962593](README/1575599962593.png)

![1578893655968](README/1578893655968.png)

