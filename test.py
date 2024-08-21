from androguard.core.apk import APK

# APK 文件路径
apk_path = "C:/python/testapk/lcsc_3.apk"
apk_ob = APK(apk_path)

result1 = apk_ob.is_signed_v1()
result2 = apk_ob.is_signed_v2()
result3 = apk_ob.is_signed_v3()
print(result1,result2,result3)
