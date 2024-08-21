import os

class pathTool:
    '''
    文件相关处理函数
    '''
    @classmethod
    def check_paths(cls,*paths) -> bool:
        '''
        描述：检测文件路径是否存在
        参数值：path元组
        '''
        for path in paths:
            if not os.path.exists(path):
                return False
        return True
    @classmethod
    def replace_path(cls,path) -> str:
        '''
        描述：路径反斜杠替换
        参数值：字符串
        '''
        return path.replace("\\", "/")
    @classmethod
    def search_files(cls,path_all) -> list:
        '''
        描述：获取目录下，需要进行数据筛查的文件路径
        参数值：目录路径-字符串
        '''
        check_path = []
        path_all = cls.replace_path(path_all)
        if os.path.isdir(path_all):
            for root,dirs,files in os.walk(path_all):
                for file in files:
                    #文件类型白名单，只排查以下类型的文件作数据检索
                    whitelist = (
                        '.java','.json','.xml','.js','.txt','.md','.html','.Providers'
                    )
                    if file.endswith(whitelist):
                        check_path.append(os.path.join(root,file))
        else:
            print('**********请确定目录地址！*******')
            return
        return check_path
    @classmethod
    def search_files_java(cls,path_all) -> list:
        '''
        描述：获取目录下，需要进行数据筛查的文件路径
        参数值：目录路径-字符串
        '''
        check_path = []
        path_all = cls.replace_path(path_all)
        if os.path.isdir(path_all):
            for root,dirs,files in os.walk(path_all):
                for file in files:
                    #文件类型白名单，只排查以下类型的文件作数据检索
                    whitelist = (
                        '.java'
                    )
                    if file.endswith(whitelist):
                        check_path.append(os.path.join(root,file))
        else:
            print('**********请确定目录地址！*******')
            return
        return check_path