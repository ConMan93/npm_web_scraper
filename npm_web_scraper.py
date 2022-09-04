# Author: Connor Hoffman 001345531 & Gerardo Monterroza

from subprocess import DEVNULL, PIPE, STDOUT, CalledProcessError, run
from colorama import Fore, Back
import pymsteams
import colorama
import argparse
import requests
import tarfile
import shutil
import yara
import bs4 
import sys
import os

WEBHOOK_URL = 'https://westerngovernorsuniversity.webhook.office.com/webhookb2/8c7994c4-d96f-4b42-a8db-63f8ab84d9c9@cfa792cf-7768-4341-8857-81754c2afa1f/IncomingWebhook/176366163f164c0c87d31cb389e0f6d5/5091c999-0734-4e37-a913-b9dca36decbd'

def oss_gadget_analyze(package_name):
    print(Back.GREEN + "[*] Analyzing " + package_name)
    package_dir = package_name

    if package_name[0] == '@':
            package_name = package_name.replace('@', "%40")
            package_name = package_name.replace('/', "%2F")

    if quiet:
            out = run([OSS_gadget_dir + 'oss-defog', '--download-directory', '.' + dir_separator + 'npm_packages/' + package_dir, '--use-cache', 'pkg:npm/' + package_name, '--save-found-binaries-to', '.', dir_separator, 'potentially_malicious'], stdout=PIPE, stderr=DEVNULL).stdout.splitlines()
            for i in out:
                print(i.decode())
    else:
            run([OSS_gadget_dir + 'oss-defog', '--download-directory', '.' + dir_separator + 'npm_packages/' + package_dir, '--use-cache', 'pkg:npm/' + package_name, '--save-found-binaries-to', '.', dir_separator, 'potentially_malicious'])

def get_new_package_names():
    npm_package_names = []
    k = 1
    while(k < 2):
        res = requests.get('https://libraries.io/search?order=desc&platforms=npm&sort=created_at&page='+str(k))
        soup = bs4.BeautifulSoup(res.text, 'html.parser')
        i = 4 # Based on the set up of the webpage, this is the first package in the list
        while(i < 2):
            css_selector = 'body > div.container > div.row > div.col-sm-8 > div:nth-child('+str(i)+') > h5 > a'
            more_soup = soup.select(css_selector)[0]
            soup_content = more_soup.contents[0]
            # soup_urls = more_soup.attrs['href'] in case we want the links to the packages
            npm_package_names.append(soup_content)
            i += 1
        k += 1
    return npm_package_names

def get_new_package_names_mode2():
    k = 1
    while(k < 100):
        res = requests.get('https://libraries.io/search?order=desc&platforms=npm&sort=created_at&page='+str(k))
        soup = bs4.BeautifulSoup(res.text, 'html.parser')
        i = 4 # Based on the set up of the webpage, this is the first package in the list
        while(i < 34):
            css_selector = 'body > div.container > div.row > div.col-sm-8 > div:nth-child('+str(i)+') > h5 > a'
            more_soup = soup.select(css_selector)[0]
            package = more_soup.contents[0]
            # soup_urls = more_soup.attrs['href'] in case we want the links to the packages
            if package:
                oss_gadget_analyze(package)
                #extract_packages()
                #check_yara_rules_for_each()
                #clean_up()
            i += 1
        k += 1

def download_packages(package_names):
    for package in package_names:
        os.system('npm pack ' + package + ' --pack-destination .' + dir_separator + 'npm_packages' + dir_separator)

def download_package(package_name):
    print("[*] Downloading " + package_name + '!')
    if quiet:
        try:
            run(['npm', 'pack', package_name, '--pack-destination', '.' +  dir_separator + 'npm_packages' + dir_separator], stdout=DEVNULL, stderr=STDOUT)
            return True
        except CalledProcessError:
            print("[!] Error downloading " + package_name)
            return False
    else:
        try:
            run(['npm', 'pack', package_name, '--pack-destination', '.' +  dir_separator + 'npm_packages' + dir_separator])
            return True
        except CalledProcessError:
            print("[!] Error downloading " + package_name)
            return False
        

def extract_packages():
    files = os.listdir(current_working_directory + dir_separator + 'npm_packages' + dir_separator)
    for file in files:
        ext_file = tarfile.open(current_working_directory + dir_separator + 'npm_packages' + dir_separator + file)
        ext_file.extractall(current_working_directory + dir_separator + 'extracted_packages' + dir_separator + file[:-4])
        ext_file.close()

def create_card(package_name, filename, yara_matches):
    my_teams_message = pymsteams.connectorcard(WEBHOOK_URL)
    my_teams_message.title(f"Potential Malicious Package: {package_name}")
    my_teams_message.text(f"The {filename} file in the {package_name} package triggered {yara_matches} yara rules.")
    my_teams_message.send()

def load_yara_rules():
    yara_rules_dict = {}
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'yara_rules'):
        if filenames:
            for filename in filenames:
                with open(current_working_directory + dir_separator + 'yara_rules' + dir_separator + filename, 'r') as yars:
                    yara_rules_dict[filename] = yars.read()

    return yara_rules_dict

def check_yara_rules():
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'extracted_packages'):
        if filenames:
            for filename in filenames:
                yara_matches = yara_rules_compiled.match(dirpath + dir_separator + filename) 
                if yara_matches:
                    package_name = dirpath.split(dir_separator)[7]
                    # create_card(package_name, filename, yara_matches)
                    try:
                        shutil.move(dirpath + dir_separator + filename, current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name + dir_separator + filename)
                    except:
                        os.mkdir(current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name)
                        shutil.move(dirpath + dir_separator + filename, current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name + dir_separator + filename)

def check_yara_rules_for_each():
    # TODO: fix permissions error
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'extracted_packages'):
        if filenames:
            for filename in filenames:
                try:
                    yara_matches = yara_rules_compiled.match(dirpath + dir_separator + filename)
                    package_name = dirpath.split(dir_separator)[7]
                    new_dir = dirpath + dir_separator + filename, current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name + dir_separator + filename 
                    if yara_matches:
                        positive_alert(new_dir, package_name)
                except yara.Error:
                    print("[!] Permissions error! Not even bothering.")
                    # os.chmod(dirpath + dir_separator + filename, stat.S_IRWXU)
                    # if yara_matches:
                    #    positive_alert(new_dir, package_name)

def positive_alert(dir, name):
    print("Something funny!")
    # create_card(package_name, filename, yara_matches)
    try:
        shutil.move(dir)
    except:
        os.mkdir(current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + name)
        shutil.move(dir)

def clean_up():
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'npm_packages'):
        for filename in filenames:
            os.remove(dirpath + dir_separator + filename)
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'extracted_packages'):
        if dirpath != current_working_directory + dir_separator + 'extracted_packages':
            shutil.rmtree(dirpath)

def check_OS(sys_platform):
    separator = '\\'
    if sys_platform.startswith('linux') or sys_platform == 'darwin':
        separator = '/'
    elif sys_platform == 'win32':
        separator = '\\'
    return separator


def main():
    if switch == 2:
        get_new_package_names_mode2()
    else:
        #package_names = get_new_package_names()
        # download_packages(package_names)
        extract_packages()
        check_yara_rules()
        #clean_up()

    

if __name__ == '__main__':
    
    current_working_directory = os.getcwd()
    dir_separator = check_OS(sys.platform)
    colorama.init(autoreset=True)
    yara_rules = load_yara_rules()
    yara_rules_compiled = yara.compile(sources=yara_rules) # load YARA rules for compiling
    OSS_gadget_dir = '..' + dir_separator + 'OSSGadget' + dir_separator
    switch = 2
    quiet = True

    print("\n\nLoaded YARA rules:")
    for y, r in yara_rules.items():
        print(y)
    print()

    main()