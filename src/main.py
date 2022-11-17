from asyncio.windows_events import NULL
import sys

__VERSION__ = 'v0.0.1'


if __name__ == "__main__":

    if len(sys.argv) == 1: 
        print('Arguments required, try starting with "-h"')
        exit()

    # Would use a switch case but only supported in python 3.10
    if sys.argv[1] in ['-h', '--help', 'help']:
        print(f'''
VULNX {__VERSION__}

Vulnrability scanner made for a assignment, the core 
features of this is for recon and vulnrability scanning

Usage:
    python {sys.argv[0]} (command) [options]

Commands: 
    run-gui\t\tRun the program in a gui.
    recon\t\tRun the recon scan on the target.
    vuln-scan\t\tRun a vulnerability scan on the target.

Options:
    help, -h, --help\t Get help for a certain command.

        ''')

    if sys.argv[1] in ['run-gui']:
        print('coming soon...')
    
    if sys.argv[1] in ['recon', 'reconnaissance', 'rcon', 'rc']:
        if len(sys.argv) <= 2 or sys.argv[2] in ['-h', '--help', 'help']:
                    print(f'''
VULNX {__VERSION__}

Vulnrability scanner made for a assignment, the core 
features of this is for recon and vulnrability scanning

Usage:
    python {sys.argv[0]} {sys.argv[1]} (target) [options]

Options:
    help, -h, --help\t Get help for a certain command.

        ''')
