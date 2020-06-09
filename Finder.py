import requests
from bs4 import BeautifulSoup
import lxml
import time
import json
from git.repo import Repo
import os
# should be changed to your directory
with os.add_dll_directory('F:\\SciTools\\bin\\pc-win64'):
	import understand
import re

# get the vulnerability's information and save it as json
def collect_vulnerability_detail(url, code_link, patch_link_list):
	info = {}
	req = requests.get(url, timeout = 40)
	soup = BeautifulSoup(req.text, "lxml")
	info["cve_name"] = soup.find('div', class_='detail_xq w770').find('h2').text.replace('\n','').replace('\t','')
	if hasattr(soup.find('div', class_='detail_xq w770').find('ul').span, 'text') == False:
		info["cnnvd_no"] = '暂无'
	elif soup.find('div', class_='detail_xq w770').find('ul').find('span').text == '':
		info["cnnvd_no"] = '暂无'
	else:
		info["cnnvd_no"] = soup.find('div', class_='detail_xq w770').find('ul').find('span').text
		info["cnnvd_no"] = info["cnnvd_no"].split('：')[1]
	message = soup.find('div', class_='detail_xq w770').find('ul').find_all('li')
	if hasattr(message[1].a, 'text') == False:
		info["cnnvd_level"] = '暂无'
	elif message[1].a.text.replace('	','').replace('\n','').replace('\r','')== '':
		info["cnnvd_level"] = '暂无'
	else:
		info["cnnvd_level"] = message[1].a.text.replace('	','').replace('\n','').replace('\r','')
	global cve_no
	if hasattr(message[2].a, 'text') == False:
		info["cve_no"] = info["cnnvd_no"]
	elif message[2].a.text.replace('	','').replace('\n','').replace('\r','')== '':
		info["cve_no"] = info["cnnvd_no"]
	else:
		info["cve_no"] = message[2].a.text.replace(' ','').replace('	','').replace('\n','').replace('\r','')
	cve_no = info["cve_no"]
	if hasattr(message[3].a, 'text') == False:
		info["catag"] = '暂无'
	elif message[3].a.text.replace('	','').replace('\n','').replace('\r','')== '':
		info["catag"] = '暂无'
	else:
		info["catag"] = message[3].a.text.replace('	','').replace('\n','').replace('\r','')
	if hasattr(message[5].a, 'text') == False:
		info["threat_cata"] = '暂无'
	elif message[5].a.text.replace('	','').replace('\n','').replace('\r','') == '':
		info["threat_cata"] = '暂无'
	else:
		info["threat_cata"] = message[5].a.text.replace('	','').replace('\n','').replace('\r','')
	info['git_repository'] = 'https://github.com/'+code_link.split('/')[3]+'/'+code_link.split('/')[4]+'.git'
	info['reference'] = []
	for patch_link in patch_link_list:
		info['reference'].append(patch_link)
	jsonData = json.dumps(info, ensure_ascii=False)
	fileObject = open('./cve_json/'+code_link.split('/')[4]+'_'+cve_no+'.json', 'a+',encoding='utf-8')
	fileObject.write(jsonData)
	fileObject.write('\n')
	fileObject.close()
	print('-----getting vulnerability details complete-----')

def code_clone(code_link):
	download_link = 'https://github.com/'+code_link.split('/')[3]+'/'+code_link.split('/')[4]+'.git'
	to_dir = './git_repository/'+code_link.split('/')[4]
	try:
		Repo.clone_from(download_link, to_dir)
	except:
		if os.path.exists('./git_repository/'+code_link.split('/')[4]):
			print('-----duplicated project-----')
		else:
			print('something wrong happen in git clone')
	else:
		print('-----successfully download: ' + download_link + '-----')

def find_related_api(e, total_api, apis_file, commitid):
	for ref in e.refs():
		# if it's Call kind
		if ref.kindname() == 'Call':
			# if it's called  by not call
			if ref.isforward() == False:
				# if is called by a method
				if ref.ent().kindname().find('Method') != -1:
					# this api has not beed analyzed before
					if ref.ent().longname() not in total_api:
						# save the entity'information
						info = {}
						total_api.append(ref.ent().longname())
						info['commitid'] = commitid
						info['file_name'] = ref.file().longname()
						info['method_name'] = ref.ent().longname()
						info['public'] = 0
						if ref.ent().kindname().find('Public') != -1:
							info['public'] = 1
						info['vulnerable_line'] = str(ref.line())
						info['previous_method_name'] = e.longname()
						jsonData = json.dumps(info, ensure_ascii=False)
						apis_file.write(jsonData)
						apis_file.write('\n')
						find_related_api(ref.ent(), total_api, apis_file, commitid)
	
def find_vulnerable_api(db, file_name, changed_lines, apis_file, total_api, commitid):
	real_filename = file_name.split('/')[-1]
	for found_file in db.lookup(real_filename):
		if real_filename == found_file.name():
			file = found_file
			break
	# j denotes the changed_line in changed_lines
	j = 0
	# m saves the method in file, line_begin saves the method's begin line， i denotes the last entity in m
	m = []
	line_begin = []
	i = -1
	# traverse all entity in file by lexeme
	for lexeme in file.lexer():
		# if this line is changed_line-1
		if lexeme.line_begin() >= changed_lines[j]:
			# find the method includes changed_line
			k = i
			while k >= 0:
				if (line_begin[k] + m[k].metric(['CountLine'])['CountLine'] - 1) < changed_lines[j]:
					del m[k]
					del line_begin[k]
					k -= 1
					i -= 1
					continue
				# make sure this entity is not new created
				elif line_begin[k] in changed_lines:
					del m[k]
					del line_begin[k]
					k -= 1
					i -= 1
					continue
				else:
					break
			# if find the vulnerable api
			if k >= 0:
				e = m[k]
				info = {}
				begin = changed_lines[j]
				while j < len(changed_lines) and (line_begin[k] + e.metric(['CountLine'])['CountLine'] - 1) >= changed_lines[j]:
					j += 1
				end = changed_lines[j-1]
				# total_api saves all apis related to the vulnerability
				total_api.append(e.longname())
				# save the information of e
				info['commitid'] = commitid
				info['file_name'] = file.longname()
				info['method_name'] = e.longname()
				info['public'] = 0
				if e.kindname().find('Public') != -1:
					info['public'] = 1
				if begin == end:
					info['vulnerable_line'] = str(begin)
				elif begin != end:
					info['vulnerable_line'] = '[' + str(begin) + ',' + str(end) + ']'
				info['previous_method_name'] = e.longname()
				jsonData = json.dumps(info, ensure_ascii=False)
				apis_file.write(jsonData)
				apis_file.write('\n')
				# find other related apis to this api
				find_related_api(e, total_api, apis_file, commitid)
			# if dosen't find the vulnerable api
			if k == -1:
				j += 1
			if j >= len(changed_lines):
				break
		if lexeme.ent():
			e = lexeme.ent()
			# if the entity is a method
			if e.kindname().find('Method') != -1:
				# if the entity is defined in this file
				e1 = e
				while 1:
					if e1.parent() == None:
						break
					e1 = e1.parent()
				if e1.name() == file_name.split('/')[-1]:
					# if the entity includes the changed code
					if e.metric(['CountLine'])['CountLine'] == None:
						continue
					if (lexeme.line_begin() + e.metric(['CountLine'])['CountLine'] - 1) >= changed_lines[j]:
						m.append(e)
						line_begin.append(lexeme.line_begin())
						i += 1

def find_changed_code_pull(pull_link, project_dir, apis_file, total_api):
	commits_link = pull_link + '/commits'
	# get commit page in commits page
	commits_req = requests.get(commits_link, timeout = 40)
	commits_soup = BeautifulSoup(commits_req.text, "lxml")
	commits_msg = commits_soup.find('div', class_ = 'commits-listing commits-listing-padded js-navigation-container js-active-navigation-container').find_all('li')
	for commit_msg in commits_msg:
		commit_href = commit_msg.find('div', class_ = 'table-list-cell').find('a', class_ = 'message js-navigation-open')['href']
		patch_link = 'https://github.com' + commit_href
		# look up the commitid in the commit page
		patch_req = requests.get(patch_link, timeout = 40)
		patch_soup = BeautifulSoup(patch_req.text, "lxml")
		commitid = patch_soup.find('div', class_ = 'commit-meta clearfix p-2 no-wrap d-flex flex-items-center').find('span', class_ = 'sha user-select-contain').text
		message_all = patch_soup.find_all('div', class_ = 'file js-file js-details-container js-targetable-element Details Details--on open show-inline-notes')
		try:
			# change the project version
			repo = Repo(project_dir)
			repo.git.checkout(commitid)
			repo.close()
			print('-----successfully change to commit: ' + commitid + '-----')
		except:
			info = {}
			info['error'] = 'change to commit ' + commitid + ' failed'
			jsonData = json.dumps(info, ensure_ascii=False)
			apis_file.write(jsonData)
			apis_file.write('\n')
			continue
		# create and open an udb
		udbfile = project_dir + '/' + project_dir.split('/')[-1] + '.udb'
		os.system('und create -languages Java ' + udbfile)
		os.system('und add ' + project_dir + ' ' + udbfile)
		os.system('und analyze ' + udbfile)
		db = understand.open(udbfile)
		# look up changed files and lines in commit page
		for message in message_all:
			changed_lines = []
			file_name = message.find('div', class_ = 'file-info flex-auto').find('a').text
			if file_name.find('.java') == -1:
				continue
			message1_all = message.find('div', class_ = 'data highlight js-blob-wrapper').find_all('td', class_ = 'blob-num blob-num-addition js-linkable-line-number')
			message2_all = message.find('div', class_ = 'data highlight js-blob-wrapper').find_all('span', attrs = {'class':'blob-code-inner blob-code-marker','data-code-marker':'+'})
			if message1_all == None:
				continue
			for k in range(len(message1_all)):
				# if it's a blank line
				if message2_all[k].find('span') == None:
					continue
				# if it's a comment
				if message2_all[k].find('span', class_ = 'pl-c') != None:
					continue
				message3 = message1_all[k]['data-line-number']
				changed_lines.append(int(message3))
			print('-----find changed_lines in file : ' + file_name + '-----')
			# use understand tool to analyze the vulnerability in this file
			find_vulnerable_api(db, file_name, changed_lines, apis_file, total_api, commitid)
			print('-----vulnerable_api analyze done-----')
		db.close()
		os.remove(udbfile)

def find_changed_code_commit(patch_link, project_dir, apis_file, total_api):
	# look up the commitid in the commit page
	patch_req = requests.get(patch_link, timeout = 40)
	patch_soup = BeautifulSoup(patch_req.text, "lxml")
	commitid = patch_soup.find('div', class_ = 'flex-auto no-wrap text-lg-right text-left overflow-x-auto').find('span', class_ = 'sha user-select-contain').text
	message_all = patch_soup.find_all('div', class_ = 'file js-file js-details-container js-targetable-element Details Details--on open show-inline-notes')
	is_error = 0
	try:
		# change the project version
		repo = Repo(project_dir)
		repo.git.checkout(commitid)
		repo.close()
		print('-----successfully change to commit: ' + commitid + '-----')
	except:
		info = {}
		info['error'] = 'change to commit ' + commitid + ' failed'
		jsonData = json.dumps(info, ensure_ascii=False)
		apis_file.write(jsonData)
		apis_file.write('\n')
		is_error = 1
	if not is_error:
		# create and open an udb
		udbfile = project_dir + '/' + project_dir.split('/')[-1] + '.udb'
		os.system('und create -languages Java ' + udbfile)
		os.system('und add ' + project_dir + ' ' + udbfile)
		os.system('und analyze ' + udbfile)
		db = understand.open(udbfile)
		# look up changed files and lines in commit page
		for message in message_all:
			changed_lines = []
			file_name = message.find('div', class_ = 'file-info flex-auto min-width-0 mb-md-0 mb-2').find('a').text
			if file_name.find('.java') == -1:
				continue
			message1_all = message.find('div', class_ = 'data highlight js-blob-wrapper').find_all('td', class_ = 'blob-num blob-num-addition js-linkable-line-number')
			if message1_all == None:
				continue
			for message1 in message1_all:
				message2 = message1['data-line-number']
				changed_lines.append(int(message2))
			if changed_lines == []:
				continue
			print('-----find changed_lines in file : ' + file_name + '-----')
			# use understand tool to analyze the vulnerability in this file
			find_vulnerable_api(db, file_name, changed_lines, apis_file, total_api, commitid)
			print('-----vulnerable_api analyze done-----')
		db.close()
		os.remove(udbfile)

def get_vulnerability_detail(url_now):
	url = 'http://www.cnnvd.org.cn'+url_now
	req = requests.get(url, timeout = 40)
	soup = BeautifulSoup(req.text, "lxml")
	cve_link = soup.find('div', class_ = 'detail_xq w770').find('ul').find_all('li')[2].a['href']
	# if the cve_link exists
	if cve_link.split('=')[1] != '':
		cve_req = requests.get(cve_link, timeout = 40)
		if cve_req.status_code == 200:
			cve_soup = BeautifulSoup(cve_req.text, "lxml")
			print(cve_link)
			patch_link_list = []
			patch_found = 0
			if hasattr(cve_soup.find('div', id = 'GeneratedTable').find_all('tr')[6].find('td').find('ul'), 'href') == True:
				code_link_list = cve_soup.find('div', id = 'GeneratedTable').find_all('tr')[6].find('td').find('ul').find_all(href=True)
				# if the project is in github
				for code_link_a in code_link_list:
					code_link = code_link_a['href']
					if code_link.find('https://github.com') != -1 and code_link.count('/') > 4 and (code_link.split('/')[5] == 'pull' or code_link.split('/')[5] == 'commit'):
						patch_link_list.append(code_link)
						patch_found = 1
			if patch_found:
				code_link = patch_link_list[0]
				download_link = 'https://github.com/'+code_link.split('/')[3]+'/'+code_link.split('/')[4]+'.git'
				git_req = requests.get(download_link, timeout = 40)
				if git_req.status_code == 200:
					git_soup = BeautifulSoup(git_req.text, "lxml")
					print('-----github project found: ' + code_link + '-----')
					# if there is a project language judgment exists in the github page
					if git_soup.find('div', class_ = 'repository-content').find_all(lambda tag: tag.name=='details' and tag.get('class')==['details-reset']) != []:
						# if it's Java project
						if git_soup.find('div', class_ = 'repository-content').find('details', class_ = 'details-reset').find('div', class_ = 'd-flex repository-lang-stats-graph').find('span').text == 'Java':
							print('-----Java github project found: ' + code_link + '-----')
							collect_vulnerability_detail(url, code_link, patch_link_list)
							# code_clone(code_link)
							apis_file = open('./api_json/'+code_link.split('/')[4]+'_'+cve_no+'.json', 'a+',encoding='utf-8') 
							project_dir = './git_repository/'+code_link.split('/')[4]
							total_api = []
							for patch_link in patch_link_list:
								if patch_link.split('/')[5] == 'commit':
									find_changed_code_commit(patch_link, project_dir, apis_file, total_api)
								elif patch_link.split('/')[5] == 'pull':
									patch_link = 'https://github.com/'+patch_link.split('/')[3]+'/'+patch_link.split('/')[4]+'/pull/'+patch_link.split('/')[6]
									find_changed_code_pull(patch_link, project_dir, apis_file, total_api)
							apis_file.close()

# get total pages count
def get_all_page():
	global all_page
	req = requests.get('http://www.cnnvd.org.cn/web/vulnerability/querylist.tag',timeout=40)
	soup = BeautifulSoup(req.text, "lxml")
	message = soup.find('div', class_='page').find('a')
	if hasattr(message, 'text') == False:
		all_page = 1
	else:
		all_message = int(message.text.split('：')[1].replace(',',''))
		if all_message % 10 != 0:
			all_page = int(all_message / 10) + 1
		else:
			all_page = int(all_message / 10)
	print('total pages: ' + str(all_page))

# get all vulnerabilities' links in the page of now_url
def get_now_page_all_url(now_url):
	req = requests.get(now_url, timeout = 40)
	soup = BeautifulSoup(req.text, "lxml")
	message = soup.find('div', class_='list_list').find('ul').find_all('li')
	for data in message:
		get_vulnerability_detail(data.div.a['href'])

# the start function
def start():
	get_all_page()
	try:
		for now_page in range(1, all_page):
			print(now_page)
			get_now_page_all_url('http://www.cnnvd.org.cn/web/vulnerability/querylist.tag?pageno=' + str(now_page) + '&repairLd=')
			print('end')
	except:
		print('error')
