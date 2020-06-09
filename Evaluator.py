import os
import requests
from bs4 import BeautifulSoup
import json

def compute_project_star_fork():
	filelist = os.listdir('./api_json')
	star_count = 0
	fork_count = 0
	for file in filelist:
		with open('./cve_json/'+file,'r',encoding='utf-8')as fp:
			for line in fp:
				item = json.loads(line)
				cnnvd_no = item['cnnvd_no']
				url = 'http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD='+cnnvd_no
				req = requests.get(url, timeout = 40)
				soup = BeautifulSoup(req.text, "lxml")
				cve_link = soup.find('div', class_ = 'detail_xq w770').find('ul').find_all('li')[2].a['href']
				cve_req = requests.get(cve_link, timeout = 40)
				cve_soup = BeautifulSoup(cve_req.text, "lxml")
				code_link_list = cve_soup.find('div', id = 'GeneratedTable').find_all('tr')[6].find('td').find('ul').find_all(href=True)
				for code_link_a in code_link_list:
						code_link = code_link_a['href']
						if code_link.find('https://github.com') != -1:
							refer = code_link
							break
				link = 'https://github.com/' + refer.split('/')[3] + '/' + refer.split('/')[4]
				break
		req = requests.get(link, timeout = 40)
		soup = BeautifulSoup(req.text, "lxml")
		message = soup.find('div',class_ = 'pagehead repohead hx_repohead readability-menu bg-gray-light pb-0 pt-3').find('ul',class_ = 'pagehead-actions flex-shrink-0').find_all('li')
		star = message[-2].find('a',class_ = 'social-count js-social-count')['aria-label']
		fork = message[-1].find('a',class_ = 'social-count')['aria-label']
		star_num = int(star.split(' ')[0])
		fork_num = int(fork.split(' ')[0])
		print(cnnvd_no, star_num, fork_num)
		star_count += star_num
		fork_count += fork_num
	print('star_count = ',end='')
	print(star_count)
	print('fork_count = ',end='')
	print(fork_count)
	
def compute_vulnerable_api_num():
	filelist = os.listdir('./api_json')
	for file in filelist:
		with open('./api_json/'+file,'r',encoding='utf-8')as fp1:
			count = 0
			for line in fp1:
				count += 1
		with open(+'./cve_json/'+file,'r',encoding='utf-8')as fp2:
			for line in fp2:
				item = json.loads(line)
				cnnvd_no = item['cnnvd_no']
		print(cnnvd_no, count)