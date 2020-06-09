# Introduction

This is a software third-party vulnerable API mining system. It aims to mine the information of API related to existing vulnerabilities.

# Files

main.py: the main function of this tool.

Finder.py: find qualified CNNVD vulnerabilities and related APIs.

jar.py: find the jar information of projects.

Evaluate.py: evaluate the influence of analyzed project and how many vulnerable APIs it has.

Saver.py: save the vulnerable APIs into database.

【Besides, you should create these folders in project directory.】

cve_json folder: stores vulnerabilities' coarse-grained information. Name: 'cve_json'.

api_json folder: stores the information of APIs related to vulnerabilities. Name: 'api_json'.

jar_json folder: stored the jar information of projects. Name: 'jar_json'

git_repository folder: stores repositories of projects. Name: 'git_repository'.

# Usage

You need to install a code analysis tools named Scitools Understand.

Using Understand Python API, you need to configure first. 

Follow the steps in https://scitools.com/support/python-api/.

Before running, you should changed the directory above 'import understand' in Finder.py

You can run python main.py -h to get the help information.

If you want to analyze all vulnerabilities in CNNVD (China National Vulnerability Database of Information Security), you can input 'python main.py -a 1 <-e n> <-s 1>'. -e and -s are optional which means evaluating and saving.

If you want to analyze the related APIs from given project, file and column, you can input 'python main.py -p project_name -f file_name -l line_number'. The project should be stored in git_repository folder.

Besides, you can evaluate or save separately by inputting 'python main.py -e 1' or 'python main.py -s 1'.
