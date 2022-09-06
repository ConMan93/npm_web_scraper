# Author: Connor Hoffman 001345531 & Gerardo Monterroza

from pydoc import describe
from subprocess import DEVNULL, PIPE, STDOUT, CalledProcessError, TimeoutExpired, run
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

def oss_gadget_analyze(package_name, quiet):
    """ Creates process for OSSGadget Download for provided package name. """
    print(Back.GREEN + "[*] Downloading " + package_name)
    package_dir = package_name

    if package_name[0] == '@':
            package_name = package_name.replace('@', "%40")
            package_name = package_name.replace('/', "%2F")

    if quiet:
        try:
            out = run([OSS_gadget_dir + 'oss-download', '--download-directory', '.' + dir_separator + 'npm_packages' + dir_separator + package_dir, '--extract', 'pkg:npm/' + package_name], stdout=PIPE, stderr=DEVNULL, timeout=60).stdout.splitlines()
            for i in out:
                print(i.decode())
        except TimeoutExpired:
            print(Back.RED + "[!] Process for " + package_name + " timeout'd!")
    else:
            run([OSS_gadget_dir + 'oss-defog', '--download-directory', '.' + dir_separator + 'npm_packages' + dir_separator + package_dir, '--use-cache', 'pkg:npm/' + package_name])


def get_new_package_names_list() -> list:
    """ Gathers a list of recently added packages and returns a list to download once completed. """
    npm_package_names = []
    k = 1
    while(k < 2):
        try:
            res = requests.get('https://libraries.io/search?order=desc&platforms=npm&sort=created_at&page='+str(k))
            soup = bs4.BeautifulSoup(res.text, 'html.parser')
            i = 4 # Based on the set up of the webpage, this is the first package in the list
            while(i < 2):
                css_selector = 'body > div.container > div.row > div.col-sm-8 > div:nth-child('+str(i)+') > h5 > a'
                more_soup = soup.select(css_selector)[0]
                package = more_soup.contents[0]
                # soup_urls = more_soup.attrs['href'] in case we want the links to the packages
                npm_package_names.append(package)
                i += 1
            k += 1
        except ConnectionError:
            print(Back.RED + "[!!] Connection Lost")
    return npm_package_names

def get_new_package_names(mode='OSS', quiet=True) -> int:
    """ Gathers recently added names of packages from libraries.io and feeds each to OSSGadget function. Returns total amount of downloads. """
    package_count = 0


    k = 1
    while(k < 100):
        try:
            res = requests.get('https://libraries.io/search?order=desc&platforms=npm&sort=created_at&page='+str(k))
            soup = bs4.BeautifulSoup(res.text, 'html.parser')
            i = 4 # Based on the set up of the webpage, this is the first package in the list
            while(i < 34):
                css_selector = 'body > div.container > div.row > div.col-sm-8 > div:nth-child('+str(i)+') > h5 > a'
                more_soup = soup.select(css_selector)[0]
                package = more_soup.contents[0]
                # soup_urls = more_soup.attrs['href'] in case we want the links to the packages
                if package:
                    if mode == 'OSS':
                        oss_gadget_analyze(package, quiet)
                        package_count += 1
                    elif mode =='NPM':
                        download_package_NPM(package)
                        package_count += 1
                i += 1
            k += 1
        except ConnectionError:
            print(Back.RED + "[!!] Connection Lost")

    return package_count

def download_packages(package_names):
    """ Download a list of packages. """
    for package in package_names:
        os.system('npm pack ' + package + ' --pack-destination .' + dir_separator + 'npm_packages' + dir_separator)

def download_package_NPM(package_name):
    """ Download individual package using NPM. """
    
    if quiet:
        try:
            run(['npm', 'pack', package_name, '--pack-destination', '.' +  dir_separator + 'npm_packages' + dir_separator], stdout=DEVNULL, stderr=STDOUT)
            print("[*] Downloaded " + package_name + '!')
            return True
        except CalledProcessError:
            print("[!] Error downloading " + package_name)
            return False
    else:
        try:
            run(['npm', 'pack', package_name, '--pack-destination', '.' +  dir_separator + 'npm_packages' + dir_separator])
            print("[*] Downloaded " + package_name + '!')
            return True
        except CalledProcessError:
            print("[!] Error downloading " + package_name)
            return False
        

def extract_packages():
    """ Extract packages using tarfile. Useful if using NPM mode. """
    files = os.listdir(current_working_directory + dir_separator + 'npm_packages' + dir_separator)
    for file in files:
        ext_file = tarfile.open(current_working_directory + dir_separator + 'npm_packages' + dir_separator + file)
        ext_file.extractall(current_working_directory + dir_separator + 'extracted_packages' + dir_separator + file[:-4])
        ext_file.close()

def create_card(package_name, filename, yara_matches):
    """ 
    Sends an alert to the provided webhook. 
    TODO: Make this not rely on an outside variable..
    """
    if WEBHOOK_URL:
        my_teams_message = pymsteams.connectorcard(WEBHOOK_URL)
        my_teams_message.title(f"Potential Malicious Package: {package_name}")
        my_teams_message.text(f"The {filename} file in the {package_name} package triggered {yara_matches} yara rules.")
        my_teams_message.send()
    else:
        print("No valid webhook provided.")

def load_yara_rules(directory) -> dict:
    """ Loads YARA rules from directory and creates/return dictionary. """
    yara_rules_dict = {}
    yar_directory = directory

    for (dirpath, dirname, filenames) in os.walk(yar_directory):
        if filenames:
            for filename in filenames:
                with open(directory + dir_separator + filename, 'r') as yars:
                    yara_rules_dict[filename] = yars.read()

    return yara_rules_dict

def check_yara_rules() -> int:
    """ Loads YARA dictionary. Check for matches and calls functions for sending alert to Teams and copy matches to potentially_malicious folder. """
    # TODO: fix permissions error
    triggered_YARA = 0
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'npm_packages'):
        if filenames:
            for filename in filenames:
                try:
                    print(Back.BLUE + "[!] Analyzing " + dirpath + filename + " with YARA!")
                    yara_matches = yara_rules_compiled.match(dirpath + dir_separator + filename)
                    package_name = dirpath.split(dir_separator)[7]
                    new_folder = current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name + dir_separator
                    new_dir = current_working_directory + dir_separator + 'potentially_malicious' + dir_separator + package_name + dir_separator + filename
                    if yara_matches:
                        print(Back.RED + "[!!] YARA MATCH FOR " + filename)
                        create_card(package_name, filename, yara_matches)
                        positive_alert_copy_file(new_dir, dirpath + dir_separator + filename, new_folder)
                        triggered_YARA += 1
                except yara.Error:
                    print("[!] Permissions error! Not even bothering.")
                    # os.chmod(dirpath + dir_separator + filename, stat.S_IRWXU)
                    # if yara_matches:
                    #    positive_alert(new_dir, package_name)

    return triggered_YARA

def positive_alert_copy_file(dir, name, folder):
    """ Moves provided file to a separate folder. """
    try:
        shutil.copy(name, dir)

    except FileNotFoundError:

        os.mkdir(folder)
        shutil.copy(name, dir)

def clean_up():
    """ Delete all packages that were not detected as malicious. """
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'npm_packages'):
        for filename in filenames:
            os.remove(dirpath + dir_separator + filename)
    for (dirpath, dirname, filenames) in os.walk(current_working_directory + dir_separator + 'extracted_packages'):
        if dirpath != current_working_directory + dir_separator + 'extracted_packages':
            shutil.rmtree(dirpath)

def check_OS(sys_platform) -> str:
    """ Check what operating system the script is running on. Returns the correct directory separator. """
    separator = '\\'
    if sys_platform.startswith('linux') or sys_platform == 'darwin':
        separator = '/'
    elif sys_platform == 'win32':
        separator = '\\'
    return separator


if __name__ == '__main__':
    pars = argparse.ArgumentParser(prog='NPM Web Scraper', usage="""
    python .\\npm_web_scrapper.py [--oss OR --npm] [--yars] *yara rules directory*', description='libraries.io scrapper with OSSGadget and YARA integration.
    Modify WEB_HOOKURL for Microsoft Teams alerts.
    """)
    pars.add_argument('--oss', required=False, action='store', type=str, help="Runs in OSSGadget mode. Provide directory to binaries. ex. '../OSSGadget/")
    pars.add_argument('--npm', required=False, action='store_true', help="Runs in NPM mode. Requires present NPM install.")
    pars.add_argument('--list', required=False, action='store_true')
    pars.add_argument('--yars', required=False, action='store', type=str, help="Directory to yara rules.")
    pars.add_argument('-v', '--verbose', required=False, action='store_true')
    args = pars.parse_args()

    if len(sys.argv) == 1:
        pars.print_help()
    else:
        current_working_directory = os.getcwd()
        dir_separator = check_OS(sys.platform)
        colorama.init(autoreset=True)
        package_count = 0
        YARA_triggers = 0
        yara_rules = {}

        if args.verbose:
            quiet = False
        else:
            quiet = True

        WEBHOOK_URL = ''

        if args.yars:
            yara_rules = load_yara_rules(args.yars)
            print("\n\nLoaded YARA rules:")

            for y, r in yara_rules.items():
                print(y)
            print()

            yara_rules_compiled = yara.compile(sources=yara_rules) # load YARA rules for compiling

        if args.npm:
            try:
                if args.list:
                    package_names = get_new_package_names_list()
                    download_packages(package_names)
                    extract_packages()
                else:
                    package_count = get_new_package_names(mode='NPM', quiet=quiet)
            except FileNotFoundError:
                print("[!!] Could not run NPM. Please verify installation.")

        if args.oss:
            OSS_gadget_dir = '..' + dir_separator + 'OSSGadget' + dir_separator
            package_count = get_new_package_names(mode='OSS', quiet=quiet)

        if yara_rules:
            YARA_triggers = check_yara_rules()
            print("\n\nYARA triggers: " + str(YARA_triggers))

        if package_count:
            print("Downloaded packages: " + str(package_count))
        
