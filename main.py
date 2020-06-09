import optparse
import Finder
import os
import Evaluator
import Saver
import jar

def main():
	usage = 'python %prog [-p <project> -f <file> -l <lines> -e <evaluate> -s <save>]'
	parser = optparse.OptionParser(usage)
	parser.add_option('-a', '--all', dest = 'All', type = 'int', default = 0, help = 'input "-a 1" to find all qualified cnnvd and apis')
	parser.add_option('-p', '--project', dest = 'Project', type = 'string', help = 'Java project directory')
	parser.add_option('-f', '--file', dest = 'File', type = 'string', help = 'vulnerable file in project')
	parser.add_option('-l', '--line', dest = 'Line', type = 'int', help = 'vulnerable line')
	parser.add_option('-e', '--evaluate', dest = 'Evaluate', type = 'int', default = 0, help = 'input "-e 1" to compute projects\' stars and forks, input "-e 2" to compute projects\' vulnerable api num, input "-e 3" to compute both')
	parser.add_option('-s', '--save', dest = 'Save', type = 'int', default = 0, help = 'input "-s 1" to save into database')
	options, args=parser.parse_args()
	if options.All == 1:
		Finder.start()
		jar.find_jars()
		if options.Evaluate == 1:
			Evaluator.compute_project_star_fork()
		elif options.Evaluate == 2:
			Evaluator.compute_vulnerable_api_num()
		elif options.Evaluate == 3:
			Evaluator.compute_project_star_fork()
			Evaluator.compute_vulnerable_api_num()
		if options.Save == 1:
			Saver.save_api_into_database()
			Saver.save_vul_into_database()
	elif options.Project != None and options.File != None and options.Line != None:
		udbfile = options.Project + '.udb'
		os.system('und create -languages Java ' + udbfile)
		os.system('und add ' + options.Project + ' ' + udbfile)
		os.system('und analyze ' + udbfile)
		db = understand.open(udbfile)
		lines = []
		lines.append(str(options.Line))
		apis_file = open('./api_json/'+options.Project+'.json', 'a+',encoding='utf-8') 
		total_api = []
		Finder.find_vulnerable_api(db, file_name, lines, apis_file, total_api)
		jar.find_jar(options.Project)
	else:
		if options.Evaluate != 0:
			if options.Evaluate == 1:
				Evaluator.compute_project_star_fork()
			elif options.Evaluate == 2:
				Evaluator.compute_vulnerable_api_num()
			elif options.Evaluate == 3:
				Evaluator.compute_project_star_fork()
				Evaluator.compute_vulnerable_api_num()
			if options.Save == 1:
				Saver.save_api_into_database()
				Saver.save_vul_into_database()
		else:
			if options.Save == 1:
				Saver.save_api_into_database()
				Saver.save_vul_into_database()
			else:
				print('you should input project, file and line at the same time!')


if __name__ == '__main__':
    main()