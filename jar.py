import os
import jsonlines
import json
import re
from xml.dom.minidom import parse

def replace_maven(str, root, dir):
	if str.find('${') != -1:
		l = re.split("\$|{|}", str)
		i = 2
		while i < len(l):
			if l[i].find('project.') != -1:
				a = l[i].split('project.')[1]
				ss=root.getElementsByTagName(a)
				for s in ss:
					if s.parentNode != root:
						continue
					l[i] = s.childNodes[0].data
					break
			else:
				a = l[i]
				l[i] = root.getElementsByTagName(a)[0].childNodes[0].data
			i = i + 3
		str = ''.join(l)
		str = replace_maven(str, root, dir)
		return str
	else:
		return str

def replace_ant(str, root, dir):
	if str.find('${') != -1:
		files = root.getElementsByTagName('property')
		names = root.getElementsByTagName('property')
		l = re.split("\$|{|}", str)
		i = 2
		while i < len(l):
			find = 0
			for name in names:
				if name.hasAttribute('name'):
					if name.getAttribute('name') == l[i]:
						if name.hasAttribute('value'):
							l[i] = name.getAttribute('value')
						elif name.hasAttribute('location'):
							l[i] = name.getAttribute('location')
						find = 1
						break
			if find == 1:
				i = i + 3
				continue
			find = 0
			for file in files:
				if file.hasAttribute('file'):
					file_dir = dir + '/' + file.getAttribute('file')
					if os.path.exists(file_dir) == 0:
						continue
					fp = open(file_dir, 'r')
					for line in fp:
						if line.find(l[i]) != -1:
							l[i] = line.split('=')[1]
							l[i] = l[i].replace('\n','').replace('\t','')
							find = 1
							fp.close()
							break
				if find == 1:
					break
			i = i + 3
		str = ''.join(l)
		str = replace_ant(str, root, dir)
		return str
	else:
		return str

def find_jar_maven(dir, info):
	xml_file = dir + '/pom.xml'
	doc=parse(xml_file)
	root=doc.documentElement
	parent=root.getElementsByTagName('parent')
	groupIds=root.getElementsByTagName('groupId')
	for groupId in groupIds:
		if groupId.parentNode != root:
			continue
		info['groupId'] = replace_maven(groupId.childNodes[0].data, root, dir)
	if 'groupId' not in info:
		info['groupId'] = replace_maven(parent[0].getElementsByTagName('groupId')[0].childNodes[0].data, root, dir)
	artifactIds=root.getElementsByTagName('artifactId')
	for artifactId in artifactIds:
		if artifactId.parentNode != root:
			continue
		info['artifactId'] = replace_maven(artifactId.childNodes[0].data, root, dir)
	versions=root.getElementsByTagName('version')
	for version in versions:
		if version.parentNode != root:
			continue
		info['version'] = replace_maven(version.childNodes[0].data, root, dir)
	if 'version' not in info:
		info['version'] = replace_maven(parent[0].getElementsByTagName('version')[0].childNodes[0].data, root, dir)
	packagings=root.getElementsByTagName('packaging')
	for packaging in packagings:
		if packaging.parentNode != root:
			continue
		info['packaging'] = replace_maven(packaging.childNodes[0].data, root, dir)
	if 'packaging' not in info:
		info['packaging'] = 'jar'
	build_all = root.getElementsByTagName('build')
	if build_all != []:
		for build in build_all:
			finalName_all = build.getElementsByTagName('finalName')
			if finalName_all != []:
				for finalName in finalName_all:
					if finalName.parentNode != build:
						continue
					jar_name = finalName.childNodes[0].data + '.' + info['packaging']
					info['jar'] = replace_maven(jar_name, root, dir)
	if 'jar' not in info:
		plugins_all = root.getElementsByTagName('plugins')
		if plugins_all != []:
			for plugins in plugins_all:
				if 'jar' in info:
					break
				plugin_all = plugins.getElementsByTagName('plugin')
				for plugin in plugin_all:
					artifactId = plugin.getElementsByTagName('artifactId')[0].childNodes[0].data
					if artifactId in ['maven-jar-plugin','maven-assembly-plugin','maven-shade-plugin','maven-source-plugin']:
						finalName = plugin.getElementsByTagName('finalName')
						if finalName != []:
							finalName = plugin.getElementsByTagName('finalName')[0].childNodes[0].data
							jar_name = finalName + '.' + info['packaging']
							info['jar'] = replace_maven(jar_name, root, dir)
						break
	if 'jar' not in info:
		info['jar'] = replace_maven(info['artifactId'] + '-' + info['version'] + '.' + info['packaging'], root, dir)
		
	

def find_jar_ant(dir, info):
	xml_file = dir + '/build.xml'
	doc=parse(xml_file)
	root=doc.documentElement
	files = root.getElementsByTagName('property')
	jar=root.getElementsByTagName('jar')
	if jar != []:
		jar = jar[0]
		if jar.hasAttribute('jarfile'):
			jar_name = jar.getAttribute('jarfile')
		if jar.hasAttribute('destfile'):
			jar_name = jar.getAttribute('destfile')
		info['jar'] = replace_ant(jar_name, root, dir)

def find_jar(file):
	dir = './git_repository/'+file
	info = {}
	filelist = os.listdir(dir)
	if 'pom.xml' in filelist:
		find_jar_maven(dir, info)
	if 'jar' not in info and 'build.xml' in filelist:
		find_jar_ant(dir, info)
	#elif 'build.gradle' in filelist:
		#find_jar_gradle()
	if 'jar' in info:
		print(info['jar'])
	jsonData = json.dumps(info, ensure_ascii=False)
	fileObject = open('./jar_json/'+file+'.json', 'a+',encoding='utf-8')
	fileObject.write(jsonData)
	fileObject.write('\n')
	fileObject.close()

def find_jars():
	filelist = os.listdir('./api_json')
	for file in filelist:
		with open('./api_json/'+file,'r',encoding='utf-8')as fp:
			find_jar(file.split('_CVE')[0])