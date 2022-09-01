# Author: Connor Hoffman 001345531

import requests
import bs4
import os
import tarfile
import yara
import pymsteams
import shutil

WEBHOOK_URL = 'https://westerngovernorsuniversity.webhook.office.com/webhookb2/8c7994c4-d96f-4b42-a8db-63f8ab84d9c9@cfa792cf-7768-4341-8857-81754c2afa1f/IncomingWebhook/176366163f164c0c87d31cb389e0f6d5/5091c999-0734-4e37-a913-b9dca36decbd'

def get_new_package_names():
    npm_package_names = []
    k = 1
    while(k < 5):
        res = requests.get('https://libraries.io/search?order=desc&platforms=npm&sort=created_at&page='+str(k))
        soup = bs4.BeautifulSoup(res.text, 'html.parser')
        i = 4 # Based on the set up of the webpage, this is the first package in the list
        while(i < 34):
            css_selector = 'body > div.container > div.row > div.col-sm-8 > div:nth-child('+str(i)+') > h5 > a'
            more_soup = soup.select(css_selector)[0]
            soup_content = more_soup.contents[0]
            # soup_urls = more_soup.attrs['href'] in case we want the links to the packages
            npm_package_names.append(soup_content)
            i += 1
        k += 1
    return npm_package_names

def download_packages(package_names):
    for package in package_names:
        os.system('npm pack ' + package + ' --pack-destination .\\npm_packages\\')

def extract_packages():
    files = os.listdir('C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\npm_packages\\')
    for file in files:
        ext_file = tarfile.open('C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\npm_packages\\' + file)
        ext_file.extractall('C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\extracted_packages\\' + file[:-4])
        ext_file.close()

def create_card(package_name, filename, yara_matches):
    my_teams_message = pymsteams.connectorcard(WEBHOOK_URL)
    my_teams_message.title(f"Potential Malicious Package: {package_name}")
    my_teams_message.text(f"The {filename} file in the {package_name} package triggered {yara_matches} yara rules.")
    my_teams_message.send()

def check_yara_rules():
    for (dirpath, dirname, filenames) in os.walk('C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\extracted_packages'):
        if filenames:
            for filename in filenames:
                rules = yara.compile(sources={
                    'namespace1':'rule dummy { condition: true }',
                    'namespace2':'rule dummy2 { condition: true }',
                    'namespace3':'rule dummy3 { condition: true }'
                    })
                yara_matches = rules.match(dirpath + '\\' + filename)
                if yara_matches:
                    package_name = dirpath.split('\\')[7]
                    create_card(package_name, filename, yara_matches)
                    try:
                        shutil.move(dirpath + '\\' + filename, 'C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\potentially_malicious\\' + package_name + '\\' + filename)
                    except:
                        os.mkdir('C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\potentially_malicious\\' + package_name)
                        shutil.move(dirpath + '\\' + filename, 'C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\potentially_malicious\\' + package_name + '\\' + filename)

def clean_up():
    for (dirpath, dirname, filenames) in os.walk('C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\npm_packages'):
        for filename in filenames:
            os.remove(dirpath + '\\' + filename)
    for (dirpath, dirname, filenames) in os.walk('C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\extracted_packages'):
        if dirpath != 'C:\\Users\\choff\\Documents\\Python_Scripts\\npm_web_scraper\\extracted_packages':
            shutil.rmtree(dirpath)

def main():
    # package_names = get_new_package_names()
    # download_packages(package_names)
    # extract_packages()
    # check_yara_rules()
    clean_up()

if __name__ == '__main__':
    main()