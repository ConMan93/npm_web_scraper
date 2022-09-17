from subprocess import DEVNULL, PIPE, STDOUT, CalledProcessError, TimeoutExpired, run, Popen
from colorama import Fore, Back
import requests
import tarfile
import bs4 
import os

class Scrapper():
    def __init__(self, cwd, dir_sep, oss_dir='', quiet=True):
        self.current_working_directory = cwd
        self.dir_separator = dir_sep
        self.oss_gadget_dir = oss_dir
        self.quiet = quiet
        pass

    def oss_gadget_analyze(self, package_name):
        """ Creates process for OSSGadget Download for provided package name. """
        print(Back.GREEN + "[*] Downloading " + package_name)
        package_dir = package_name

        if package_name[0] == '@':
                package_name = package_name.replace('@', "%40")
                package_name = package_name.replace('/', "%2F")

        if self.quiet:
            try:
                out = run([self.oss_gadget_dir + 'oss-download', '--download-directory', '.' + self.dir_separator + 'npm_packages' + self.dir_separator + package_dir, '--extract', 'pkg:npm/' + package_name], stdout=PIPE, stderr=DEVNULL, timeout=60).stdout.splitlines()
                for i in out:
                    print(i.decode())
            except TimeoutExpired:
                print(Back.RED + "[!] Process for " + package_name + " timeout'd!")
        else:
                run([self.oss_gadget_dir + 'oss-defog', '--download-directory', '.' + self.dir_separator + 'npm_packages' + self.dir_separator + package_dir, '--use-cache', 'pkg:npm/' + package_name])

    def fetch_from_NPM_registry(self, dir_to_script='scrapper.js') -> int:
        """ Runs javascript file to fetch from NPM registry. """
        package_count = 0

        try:
            out = Popen(['node', '.' + self.dir_separator + dir_to_script], stdout=PIPE)
            for package in iter(out.stdout.readline, ''):
                if package == 0:
                    return package_count
                self.oss_gadget_analyze(package.decode().strip())
                package_count += 1
            out.wait()
        except KeyboardInterrupt:
            print("\n\nExiting..\n")
            return package_count


    def get_new_package_names_list(self) -> list:
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

    def get_new_package_names(self, mode='OSS') -> int:
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
                            self.oss_gadget_analyze(package)
                            package_count += 1
                        elif mode =='NPM':
                            self.download_package_NPM(package)
                            package_count += 1
                    i += 1
                k += 1
            except ConnectionError:
                print(Back.RED + "[!!] Connection Lost")

        return package_count

    def download_packages(self, package_names):
        """ Download a list of packages. """
        for package in package_names:
            os.system('npm pack ' + package + ' --pack-destination .' + self.dir_separator + 'npm_packages' + self.dir_separator)

    def download_package_NPM(self, package_name):
        """ Download individual package using NPM. """
        
        if self.quiet:
            try:
                run(['npm', 'pack', package_name, '--pack-destination', '.' +  self.dir_separator + 'npm_packages' + self.dir_separator], stdout=DEVNULL, stderr=STDOUT)
                print("[*] Downloaded " + package_name + '!')
                return True
            except CalledProcessError:
                print("[!] Error downloading " + package_name)
                return False
        else:
            try:
                run(['npm', 'pack', package_name, '--pack-destination', '.' +  self.dir_separator + 'npm_packages' + self.dir_separator])
                print("[*] Downloaded " + package_name + '!')
                return True
            except CalledProcessError:
                print("[!] Error downloading " + package_name)
                return False
            

    def extract_packages(self):
        """ Extract packages using tarfile. Useful if using NPM mode. """
        files = os.listdir(self.current_working_directory + self.dir_separator + 'npm_packages' + self.dir_separator)
        for file in files:
            ext_file = tarfile.open(self.current_working_directory + self.dir_separator + 'npm_packages' + self.dir_separator + file)
            ext_file.extractall(self.current_working_directory + self.dir_separator + 'extracted_packages' + self.dir_separator + file[:-4])
            ext_file.close()