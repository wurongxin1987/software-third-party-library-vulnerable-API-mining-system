import json
import os

def save_api_into_database():
	data = []
	filelist = os.listdir('./api_json')
	for file in filelist:
		with open('./api_json/'+file,'r',encoding='utf-8')as fp1:
			for line in fp1:
				item = {}
				item1 = json.loads(line)
				if 'file_name' in item1:
					item['file_name'] = item1['file_name'].split('\\')[-1]
					item['class_name'] = item1['method_name'].split('.')[-2]
					item['method_name'] = item1['method_name'].split('.')[-1]
					item['vulnerable_line'] = item1['vulnerable_line']
					item['file_longname'] = item1['file_name']
					item['method_longname'] = item1['method_name']	
					item['isPublic'] = item1['public']
					item['commitid'] = item1['commitid']
					with open('./cve_json/'+file,'r',encoding='utf-8')as fp2:
						for line in fp2:
							item2 = json.loads(line)
							if 'cve_no' in item2:
								item['cve_no'] = item2['cve_no']
								if item2['cnnvd_level'] == '低危':
									item['cve_level'] = 'low'
								elif item2['cnnvd_level'] == '中危':
									item['cve_level'] = 'medium'
								elif item2['cnnvd_level'] == '高危':
									item['cve_level'] = 'high'
								elif item2['cnnvd_level'] == '超危':
									item['cve_level'] = 'severe'
								item['git_repository'] = item2['git_repository']
								with open('./jar_json/'+file.split('_CVE')[0]+'.json','r',encoding='utf-8')as fp3:
									for line in fp3:
										item3 = json.loads(line)
										if 'jar' in item3:
											item['jar_name'] = item3['jar']
										else:
											item['jar_name'] = ''
										data.append(item)
										break
								fp3.close()
							break
					fp2.close()
		fp1.close()
	str = "\r\n"
	for item in data:
		str = str + "insert into apis(cve_no,cve_level,jar_name,git_repository,commitid,file_name,class_name,method_name,isPublic,vulnerable_line,file_longname,method_longname) values "
		str = str + "('%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s','%s');\r\n" % (item['cve_no'],item['cve_level'],item['jar_name'],item['git_repository'],item['commitid'],item['file_name'],item['class_name'],item['method_name'],item['isPublic'],item['vulnerable_line'],item['file_longname'],item['method_longname'])

	import codecs
	file_object = codecs.open('./apis.sql', 'w' ,"utf-8")
	file_object.write(str)
	file_object.close()
	print("success")

def save_vul_into_database():
	data = []
	filelist = os.listdir('./api_json')
	for file in filelist:
		with open('./cve_json/'+file,'r',encoding='utf-8')as fp1:
			for line in fp1:
				item1 = json.loads(line)
				item = item1
				item['reference'] = item1['reference'][0]
				break
		fp1.close()
		with open('./jar_json/'+file.split('_CVE')[0]+'.json','r',encoding='utf-8')as fp2:
			for line in fp2:
				item2 = json.loads(line)
				if 'jar' in item2:
					item['jar_name'] = item2['jar']
				else:
					item['jar_name'] = ''
				break
		fp2.close()
		data.append(item)
	str = "\r\n"
	for item in data:
		str = str + "insert into vuls(cve_name,cnnvd_no,cnnvd_level,cve_no,catag,threat_cata,reference,jar_name,git_repository) values "
		str = str + "('%s','%s','%s','%s','%s','%s','%s','%s','%s');\r\n" % (item['cve_name'],item['cnnvd_no'],item['cnnvd_level'],item['cve_no'],item['catag'],item['threat_cata'],item['reference'],item['jar_name'],item['git_repository'])

	import codecs
	file_object = codecs.open('./vuls.sql', 'w' ,"utf-8")
	file_object.write(str)
	file_object.close()
	print("success")