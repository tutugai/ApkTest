#### 环境要求：

  * Python3

       * argparsepandas

          * androguard
          * pyopenssl==24.1.0
          * cryptography==42.0.7
          * tqdm

* Java 11 以上

#### 安装库

python -m pip install -r requirements.txt

#### 使用：

##### 帮助信息

```
python main.py -h
```

##### APK静态扫描：

```
python main.py apk_path -r
```

##### 反编译+数据检索

```
python main.py apk_path -d -a
```

##### 本地数据检索

```
python main.py apk_path -s dirpath
```



