import argparse
import os
from Android.apk_ob import apk_ob
from Check.regularCheck import regularCheck

if __name__ == "__main__":
    '''
    执行逻辑实现:
    '''
    #脚本描述：
    description = '''
    脚本描述：apk包静态扫描！
        1. 静态扫描结果
            *APK基本情况
            *权限信息分类
            *漏洞详情
        2. 反编译APK包
        3. 敏感数据、硬编码等数据检索功能
    '''
    parse = argparse.ArgumentParser(description=description,usage='Program for testing apk basic security!')
    parse.add_argument('apk_path',type=str,help='apk包位置')
    parse.add_argument('-r','--run',action='store_true',help='apk包基本静态扫描~生成html报告')
    parse.add_argument('-d','--decompile',action='store_true',help='JADX反编译')
    parse.add_argument('-o','--output_file',type=str,help='JADX反编译后文件存储位置(默认：当前目录下)')
    parse.add_argument('-a','--automatic',action='store_true',help='反编译后自动检索敏感信息等数据，结果保存至当前目录')
    parse.add_argument('-j','--jadx_path',type=str,default=os.path.join(os.getcwd(),'Tools','jadx-1.5.0','bin'),help='默认jadx位于\Tools\jadx-1.5.0，如需修改路径请指向jadx的bin目录（绝对路径）')
    parse.add_argument('-s','--sensitive',type=str,help='path目录路径-单独检索目标目录下所有文件的敏感信息等数据（选择了自动检索后，无需选择此项）')
    args = parse.parse_args()
    #用户未传参时，output_file的默认值为当前路径+apk名称
    apk_name = os.path.splitext(os.path.basename(args.apk_path))[0]
    default_outpath = os.path.join(os.getcwd(),apk_name)
    #apk对象
    apk = apk_ob(str.strip(args.apk_path))
    #根据用户输入选择执行逻辑
    if args.decompile and args.automatic and args.output_file:
        apk.decompile_apk(str.strip(args.output_file),str.strip(args.jadx_path))
        apk.add_check(regularCheck(str.strip(args.output_file),apk_name))
    elif args.decompile and args.output_file:
        apk.decompile_apk(str.strip(args.output_file),str.strip(args.jadx_path))
    elif args.decompile and args.automatic:
        apk.decompile_apk(str.strip(default_outpath),str.strip(args.jadx_path))
        apk.add_check(regularCheck(str.strip(default_outpath),apk_name))
    elif args.decompile:
        apk.decompile_apk(str.strip(default_outpath),str.strip(args.jadx_path))
    elif args.sensitive:
        apk.add_check(regularCheck(str.strip(args.sensitive),apk_name))
    if args.run:
        apk.out_info
    apk.run_checks()