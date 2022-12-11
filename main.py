import datetime
from socket import AF_INET, SOCK_STREAM, socket, getservbyport
from argparse import ArgumentParser
import pyfiglet
from termcolor import cprint
from concurrent.futures import ThreadPoolExecutor
import time
import os

 
banner = pyfiglet.figlet_format("Port Scanner", font="slant")
cprint(banner)

def arguments():
    parser = ArgumentParser(prog="Advanced Port Scanner", usage="main.py -i 127.0.0.1 -s 24 -e 1000", description=f"Starting the Scanner at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}.......", epilog="Designed by Siddharth",)

    parser.add_argument('-i','--host', metavar='', dest='host', help="enter the IP or host address to scan the ports")
    parser.add_argument('-s','--start', metavar='', dest='start', type=int, default=1, help="enter the starting port number (default is from 1)")
    parser.add_argument('-e','--end', metavar='', dest='end', type=int, default=65353, help="enter the ending port number (default is from 65353)")
    parser.add_argument('-v','--version', action="version", version="Scanner 1.0.0", help="display version")

    args = parser.parse_args()

    return args


def test_port_number(host, port):
    with socket(AF_INET, SOCK_STREAM) as sock:
        sock.settimeout(1)
        try:
            sock.connect((host, port))
            return True
        except:
            return False

def port_scan(host, ports):
    open_ports = []
    with ThreadPoolExecutor(len(ports)) as executor:
        results = executor.map(test_port_number, [host]*len(ports), ports)
        for port,is_open in zip(ports,results):
            if is_open:
                open_ports.append(port)
    return open_ports


def printServiceOnPort(portNumber, protocol):
    try:
        serviceName = getservbyport(portNumber, protocol)
        return serviceName
    except:
        return "Unknown"

def host_isup(ip_addr):
    stream = os.popen('ping -n 4 {}'.format(ip_addr))
    output = stream.read()
    if '0 received' in output:
        return False
    else:
        return True


if __name__ == "__main__":
    s = time.time()
    args = arguments()
    print(f"Initialising the scanner at {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} .........")
    time.sleep(0.5)
    print(f"Setting up the host {args.host} and checking if the host is up .....")
    HOST_UP  = host_isup(args.host)
    if HOST_UP:
        print(f"The Host {args.host} is Up ......")
        time.sleep(0.8)
        print(f"Scanning for the Open Ports .....")
        open_ports = port_scan(args.host, range(args.start, args.end))
        e = time.time()
        serviceName = "tcp"
        print('\033[4m'+'port'+'\033[0m' +"\t"+ '\033[4m'+"state"+'\033[0m' +"\t"+ '\033[4m'+"type"+'\033[0m')
        if len(open_ports) != 0 :
            for port in open_ports:
                print(f"{port}\topen\t{printServiceOnPort(port, serviceName)}")
            print("Completed the scan in: "+"{0:.3f}".format(e-s) + " seconds")
        else :
            print("no open ports found on this host ....")
    else :
        print(f"The Host {args.host} is down .....")