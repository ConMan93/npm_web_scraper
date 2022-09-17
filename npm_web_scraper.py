# Author: Connor Hoffman 001345531 & Gerardo Monterroza
import npmscrap
import colorama
import argparse
import yarahandle
import sys
import os

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
    pars.add_argument('--pub', required=False, action='store', type=str, help="Runs JS script that fetchs data from public NPM registry. Provide directory to script. ex. '../scrapper.js")
    pars.add_argument('--oss', required=False, action='store', type=str, help="Runs in OSSGadget mode. Provide directory to binaries. ex. '../OSSGadget/")
    pars.add_argument('--npm', required=False, action='store_true', help="Runs in NPM mode. Requires present NPM install.")
    pars.add_argument('--yars', required=False, action='store', type=str, help="Directory to yara rules.")
    pars.add_argument('-v', '--verbose', required=False, action='store_true')
    pars.add_argument('--list', required=False, action='store_true')
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

        scrapper = npmscrap.Scrapper(cwd=current_working_directory, dir_sep=dir_separator, quiet=quiet)

        WEBHOOK_URL = ''

        if args.yars:
            YARA_triggers = yarahandle.check_yara_rules(current_working_directory, dir_separator, args.yars)

        if args.npm:
            try:
                if args.list:
                    package_names = scrapper.get_new_package_names_list()
                    scrapper.download_packages(package_names)
                    scrapper.extract_packages()
                else:
                    package_count = scrapper.get_new_package_names(mode='NPM')
            except FileNotFoundError:
                print("[!!] Could not run NPM. Please verify installation.")

        if args.oss:
            try:
                scrapper.oss_gadget_dir = args.oss
                package_count = scrapper.get_new_package_names(mode='OSS')
            except FileNotFoundError:
                print("[!!] Coould not run OSS-Download. Please verify installation.")

        if args.pub:
            try:
                OSS_gadget_dir = '.' + dir_separator + 'OSSGadget' + dir_separator
                scrapper.oss_gadget_dir = OSS_gadget_dir
                js_script_dir = args.pub
                package_count = scrapper.fetch_from_NPM_registry()
            except FileNotFoundError:
                print("[!!] Could not run NODE. Please verify installation.")


        if YARA_triggers:
            print("\n\nYARA triggers: " + str(YARA_triggers))

        if package_count:
            print("Downloaded packages: " + str(package_count))
        
