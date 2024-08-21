import re
from tqdm import tqdm
import concurrent.futures
import yaml
from Tools.pathTool import pathTool
import os
import pandas as pd
from Check.checkBase import checkBase

class regularCheck(checkBase):
    '''
    描述：敏感信息正则数据检索
    参数：
        1. 需检索的目录
        2. 结果命名-默认apkname
    '''
    # 正则匹配：
    #     多线程并行实现对所有文件的数据检索
    #     pathTool.search_files函数：获取目录下，需要进行数据筛查的文件路径
    #     1. process_file函数：处理单个文件，返回该文件的匹配结果
    #     2. merge_results函数：将每个线程处理的结果合并到总体结果中
    #     3. check_regular函数：结合1、2 使用多线程执行匹配，生成结果
    #     4. out_excel函数：导出xlsx
    #     5. scan函数：实现父类检查方法，用于调用逻辑
    def __init__(self,path_all,apkname) -> None:
        super().__init__(path_all)
        self.apkname = apkname
    @staticmethod
    def process_file(file_path,regular,pbar) -> dict:
        #结果集(结果集的键和regular保持一直，值为列表)
        results = {key: [] for key in regular.keys()}
        with open(file_path,'r',encoding='utf-8') as f:
            lines = f.readlines()
            #遍历所有文件的所有行
            for line_number,line in enumerate(lines,start=1):
                #开始匹配正则处理
                for key,value in regular.items():
                    matches = value.finditer(line)
                    #处理结果集，将文件路径、行号、匹配内容、原文作为一个元组保存在结果列表里面，方便后续生成exlc对结果处理。
                    for match in matches:
                        results[key].append((file_path,line_number,match.group(),line.strip()))
        pbar.update(1)
        return results
    @staticmethod
    def merge_results(overall_results,file_results) -> None:
        for key in file_results:
            overall_results[key].extend(file_results[key])
    @staticmethod
    def check_regular(check_path) -> dict:
        '''
        参数值：需要进行数据检索的文件路径列表 -列表
        返回值：数据检索结果字典 -字典（字典内嵌套了元组类型）
        keys{
            '正则规则名':[(文件路径1,行号1,匹配内容1,原文1),(文件路径2,行号2,匹配内容2,原文2)]
            ......
        }
        '''
        #正则匹配规则加载
        regular = {}
        with open('regular.yaml',encoding='utf-8') as fp:
            rules = yaml.safe_load(fp)
        for key in rules['rules']:
            if key['enabled']:
                regular.update({key['id']:re.compile(key['pattern'])})
        #结果集(结果集的键和regular保持一直，值为列表)
        overall_results = {key: [] for key in regular.keys()}
        #开始处理
        print('*************数据检索开始处理**************')
        #使用线程池来处理
        with tqdm(total=len(check_path), desc="Processing files") as pbar:
            with concurrent.futures.ThreadPoolExecutor(max_workers=40) as executor:
                futures = {executor.submit(regularCheck.process_file,file_path,regular,pbar): file_path for file_path in check_path}
                for future in concurrent.futures.as_completed(futures):
                    file_results = future.result()
                    regularCheck.merge_results(overall_results,file_results)
        print('*************数据检索处理结束**************')
        return overall_results
    @staticmethod
    def out_excel(keys,apk_name) -> None:
        '''
        描述：针对正则匹配的结果生成特定表格，主要用于转化数据检索结果
        参数：正则匹配的结果集 - 字典（内有嵌套的元组类型）
        返回值：无
        '''
        #结果保存路径
        path = pathTool.replace_path(os.path.join(os.getcwd(),apk_name+'.xlsx'))
        # 如果文件已存在，直接返回，不进行后续操作
        if os.path.exists(path):
            print('结果文件已存在，请确认当前目录的xlsx结果文件路径')
            return
        #创建xlsx表格并将数据存储，字典的键做表名，其他为数据处理
        with pd.ExcelWriter(path) as wt:
            for key,value in keys.items():
                #判断是否有数据，有数据就处理，无数据就不输出
                if value:
                    df = pd.DataFrame(value,columns=['文件路径','匹配行号','匹配内容','原文行'])
                    df.to_excel(wt,sheet_name=key,index=False)
            print(f'结果文件已保存至 {path}')
    def scan(self) -> None:
        results = regularCheck.check_regular(pathTool.search_files(self.path_all))
        regularCheck.out_excel(results,self.apkname)