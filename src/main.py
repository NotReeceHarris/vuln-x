from asyncio.windows_events import NULL
import sys

__VERSION__ = 'v0.0.1'

def rcon():
    pass

def vuln():
    pass


if __name__ == "__main__":

    if len(sys.argv) == 1: 
        print('Arguments required, try starting with "-h"')
        exit()

    # Would use a switch case but only supported in python 3.10
    if sys.argv[1] in ['-h', '--help', 'help', 'h']: # Support shorthand
        print(f'''
VULNX {__VERSION__}

Vulnrability scanner made for a assignment, the core\nfeatures of this is for recon and vulnrability scanning

Usage:
    python {sys.argv[0]} (command) [options]

Commands: 
    gui\t\t\tRun the program in a gui.
    recon\t\tRun the recon scan on the target.
    vuln-scan\t\tRun a vulnerability scan on the target.
    help\t\tHelp menu. (You are here)

Options:
    -h, --help\t Get help for a certain command.

*short hand supported
        ''')

    # RUN GUI SCRIPT
    if sys.argv[1] in ['gui', 'g', 'run-gui']: # Support shorthand
        print('coming soon...')


    # RECON SCRIPT
    elif sys.argv[1] in ['recon', 'reconnaissance', 'rcon', 'rc', 'r']: # Support shorthand
        if len(sys.argv) <= 2 or sys.argv[2] in ['-h', '--help', 'help']: # Support shorthand
                    print(f'''
VULNX {__VERSION__}

Vulnrability scanner made for a assignment, the core\nfeatures of this is for recon and vulnrability scanning

Usage:
    python {sys.argv[0]} {sys.argv[1]} (target) [options]

Options:
    -c, --csv\tLoad targets from a csv.
    -h, --help\tGet help for a certain command.

*short hand supported
        ''')
        

    # VULN SCAN SCRIPT
    elif sys.argv[1] in ['vun-scan', 'vulnrability', 'vs', 'v', 'vuln']: # Support shorthand
        if len(sys.argv) <= 2 or sys.argv[2] in ['-h', '--help', 'help']: # Support shorthand
                    print(f'''
VULNX {__VERSION__}

Vulnrability scanner made for a assignment, the core\nfeatures of this is for recon and vulnrability scanning

Usage:
    python {sys.argv[0]} {sys.argv[1]} (target) [options] {"{options value}"}

Options:
    -i, --int\tHow intense you want the scan to be. (1-5)
    -c, --csv\tLoad targets from a csv.
    -h, --help\tGet help for a certain command.

*short hand supported
        ''')
    
    else:
        print('Unkown command or argument, try "-h"')
        
