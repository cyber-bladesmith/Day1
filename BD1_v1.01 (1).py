#!/usr/bin/python3

import subprocess
import os
import sys
import re
import datetime

menu_actions = {}

############################################
class Day_One:

    def __init__(self,name, clean_target_list = "", scan_ports = "", output_file = ""):
        self.name = name
        self.clean_target_list = clean_target_list
        self.output_files = {}
        self.clean_files = {}
        self.clean_target_list_files = {}
        self.scan_ports = scan_ports
        self.output_file = output_file
        self.application = ""
        self.timestamp = ('{:%Y-%m-%d_%H-%M-%S}'.format(datetime.datetime.now()))
        self.rate = ""
        self.menu_choice = ""
        self.scan_type = ""
        self.list_file_type = ""
        self.output_file_counter = 1
        self.clean_file_counter = 1
        self.clean_target_list_counter = 1
        self.clean_filename = ""
        self.banner_port = ""
        self.port_number = ""
        self.target_list = ""
        self.interface = ""
        # Menu definition
        self.menu_actions = {
            'main_menu': self.main_menu,
            '1': self.clean_IP_list,
            '2': self.select_clean_target_list,
            '3': self.ping_sweep,
            '4': self.port_scan,
            '5': self.banner_grab,
            '6': self.eyewitness_scan,
            '0': self.exit
        }
        self.ports_list = {
            '80_HTTP': '80,8000,8080,8081,8888',
            '443_HTTPS': '443,8443',
            '7_Echo': '7',
            '15_netstat': '15',
            '21_FTP': '20,21',
            '22_SSH': '22',
            '23_Telnet': '23',
            '25_SMTP': '25',
            '49_TACACS': '49',
            '67_BOOTP': '67,68',
            '79_Finger': '79',
            '115_SFTP': '115',
            '119_NNTP': '119',
            '123_NTP' : '123',
            '143_IMAP': '143',
            '179_BGP' : '179',
            '500_ISAKMP': '500',
            '520_RIP' : '520,521',
            '546_DHCPv6': '546,547',
            '1521_Oracle': '1521',
            '1433_MSSQL': '1433',
            '3306_MySQL': '3306',
            '389_LDAP': '389',
            '53_DNS': '53',
            '111_RPC': '111',
            '69_TFTP': '69',
            '139_SMB': '139,445',
            '902_VMWare': '902',
            '3389_RDP': '3389',
            '514_Syslog': '514',
            '5900_VNC': '5800,5900',
            '2049_NFS_UDP': '2049',
            '4786_Cisco': '4786',
            '110_POP3': '110',
            '623_IPMI': '623',
            '161_SNMP': '161,162',
            '16992_Intel_AMT': '16992,16993,16994,16995,664'

        }
    def add_output_files(self, output):
        self.output_files.update({self.output_file_counter: output})
        self.output_file_counter += 1

    def add_clean_files(self, clean):
        self.clean_files.update({self.clean_file_counter: clean})
        self.clean_file_counter += 1

    def add_clean_target_list(self, clean_target_list_file):
        self.clean_target_list_files.update({self.clean_target_list_counter: clean_target_list_file})
        self.clean_target_list_counter += 1

    ###################################################################################################################
    ### MENU FUNCTIONS ###
    ###################################################################################################################
    def main_menu(self):
        print(os.getcwd())
        print("BadlocK Day One Application,\n")
        print("Please make a selection:")
        print("1. Generate Clean Target List")
        print("2. Set Active Target List")
        print("3. Ping Sweep")
        print("4. Port Scan")
        print("5. Banner Grab")
        print("6. Perform Eyewitness Scan")
        print("0. Quit")
        self.menu_choice = input(" >>  ")
        self.exec_menu()

    # Execute menu
    def exec_menu(self):
        os.system('clear')
        print(self.menu_choice)
        ch = self.menu_choice.lower()
        if ch == '':
            self.menu_actions['main_menu']()
        else:
            try:
                self.menu_actions[ch]()
            except KeyError:
                print("Invalid selection, please try again.\n")
                self.menu_actions['main_menu']()
        return
    ###################################################################################################################
    ### END MENU FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### SUPPORT FUNCTIONS ###
    ###################################################################################################################
    # Clean Target List Check
    def clean_target_list_check(self):
        clean_list_check = "n"
        if self.clean_target_list != "":
            clean_list_check = input("Would you like to use the Selected IP Target List?(y/n): ")
        if clean_list_check.lower() == "n":
            target_list = input("Enter file location or CIDR notation for scan:")
        else:
            target_list = ("./clean_target_lists/" + self.clean_target_list)
        return (target_list)

    # Clean the files function
    def clean(self,output_file, scan_type):

        open_set = set()

        list_file = []
        open_ports = []
        filtered_ports = []
        raw_data = open(output_file, 'r')
        for each in raw_data.readlines():
            if scan_type == "ping":
                self.list_file_type = "ping_clean_"
                line = re.search(r'Host: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', each)
                if line:
                    clean_filename = self.application + "_" + self.name + "_" + \
                                     self.list_file_type + self.timestamp
                    clean = open(("./clean_target_lists/" + clean_filename), 'a')
                    clean.write(each.split(' ')[1] + "\n")
                    clean.close()
            if scan_type == "port":
                line = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \(\)\tPorts: \d{1,5}', each)
                if line:
                    list_file.append(each)
            if scan_type == "clean_list":
                self.list_file_type = "clean_list_"
                line = re.search(r'Host: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', each)
                if line:
                    self.clean_filename = self.name + "_" + self.list_file_type + self.timestamp
                    clean = open(("./clean_target_lists/" + self.clean_filename), 'a')
                    clean.write(each.split(' ')[1] + "\n")
                    clean.close()
            if scan_type == "banner_grab":
                self.list_file_type = "clean_"
                line = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \(\)\tPorts: \d{1,5}', each)
                if line:
                    clean_filename = self.application + "_" + scan_type + "_" + self.name + "_" + \
                                     self.port_number + "_clean_" + self.timestamp
                    clean = open(("./Enumeration/" + clean_filename), 'a')
                    clean.write(each + "\n")
                    clean.close()

        raw_data.close()
        for each in list_file:
            for socket_info in each.split(' ')[3:]:
                if '/open' in socket_info:
                    self.list_file_type = "_open_clean_"
                    open_ports.append(each.split(' ')[1] + ':' + socket_info.split('/')[0])
                elif '/filtered' in socket_info:
                    self.list_file_type = "_filtered_clean_"
                    filtered_ports.append(each.split(' ')[1] + ':' + socket_info.split('/')[0])

        for socket in open_ports:
            clean_filename = self.application + "_" + self.name + "_" + socket.split(':')[1] + \
                             self.list_file_type + self.timestamp
            clean = open(("./Enumeration/" + clean_filename), 'a')
            clean.write(socket.split(':')[0] + "\n")
            open_set.add(clean_filename)
            clean.close()

        for socket in filtered_ports:
            clean_filename = self.application + "_" + self.name + "_" + socket.split(':')[1] + \
                             self.list_file_type + self.timestamp
            clean = open(("./Enumeration/" + clean_filename), 'a')
            clean.write(socket.split(':')[0] + "\n")
            open_set.add(clean_filename)
            clean.close()
        self.load_files()
        return

    # List Directory for Port Selection
    def list_directory(self):
        # List out possible files to use
        self.port_number = input("Input port to run on: ")
        port_number_search = "_" + self.port_number + "_"
        port_counter = 1
        ls = subprocess.Popen(['ls', './Enumeration/'], stdout=subprocess.PIPE)
        output = ls.communicate()[0]
        str_output = output.decode()
        port_files = {}
        print("The following files were found in the Enumeration folder with that port:")
        for line in str_output.split('\n'):
            if port_number_search in line:
                port_files.update({port_counter: line})
                port_counter += 1
        for key, value in sorted(port_files.items()):
            print(key, value)
        select_file = input("Please enter number of file to use? (x to return to menu): ")
        try:
            if select_file.lower() == "x":
                print("\n")
                self.main_menu()
            elif int(select_file) not in port_files.keys():
                print("File does not exist.")
                self.list_directory()
            else:
                self.target_list = ("./Enumeration/" + port_files.get(int(select_file)))
        except ValueError:
            print("Invalid Selection")
            self.main_menu()

    # Back to main menu
    def back(self):
        self.main_menu()
    ###################################################################################################################
    ### END SUPPORT FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### GENERATE CLEAN TARGET LIST FUNCTIONS ###
    ###################################################################################################################
    # Target List Creation Function
    def clean_IP_list(self):
        self.scan_type = "clean_list"
        try:
            target_list = input("Enter the location of the IP target list: ")
            exclude_list = input("Enter the location of the Excluded IP list: ")
            self.output_file = self.name + "_clean_IP_raw_" + self.timestamp
            subprocess.check_output(
                ["nmap", "-sL", "-n", "-iL", target_list, "--excludefile", exclude_list,
                 "-oG", ("./clean_target_lists/" + self.output_file)])

            self.clean(("./clean_target_lists/" + self.output_file), self.scan_type)

            print("Cleaned IP Target List has been created.  Filename is " + self.clean_filename)

            self.set_active_clean_target_list(self.clean_filename)

        except subprocess.CalledProcessError:
            print("File not found.  Try again...")
            self.clean_IP_list()
    ###################################################################################################################
    ### END GENERATE CLEAN TARGET LIST FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### SET ACTIVE TARGET LIST FUNCTIONS ###
    ###################################################################################################################
    # Set active clean target list
    def set_active_clean_target_list(self,clean_IP_output_file):
        while True:
            set_active = input("Would you like to set this as the active clean target list? (y/n)")
            if set_active.lower() == "y":
                self.clean_target_list = clean_IP_output_file
                break
            elif set_active.lower() == "n":
                break
            else:
                print("Invalid input.")
        self.main_menu()

    # Select the select clean target list
    def select_clean_target_list(self):
        print("The current active clean target list is " + self.clean_target_list)
        for key, value in self.clean_target_list_files.items():
            print(key, value)
        active_list = input("Please enter number of file to activate (x to return to main menu): ")
        if active_list.lower() == "x":
            print("\n")
            self.main_menu()
        elif int(active_list) not in self.clean_target_list_files.keys():
            print("File does not exist.")
            self.select_clean_target_list()
        else:
            self.clean_target_list = self.clean_target_list_files.get(int(active_list))
            print("Active clean target list is set to " + self.clean_target_list + "\n")
        self.main_menu()
        return
    ###################################################################################################################
    ### END SET ACTIVE TARGET LIST FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### SCAN SETTINGS FUNCTIONS ###
    ###################################################################################################################

    def scan_settings(self):
        try:
            application = input("Nmap or Masscan? (n/m): ")
            while True:
                if application.lower() == "n":
                    self.application = "nmap"
                    rate = "-" + input("Enter Nmap rate (ex. T5):")
                    self.rate = rate.upper()
                elif application.lower() == "m":
                    self.application = "masscan"
                    self.rate = "--rate=" + input("Enter masscan rate (ex. 1000):")
                else:
                    application = input("Nmap or Masscan? (n/m): ")

    # This if statement is to for scan type settings (port or ping)
                if self.scan_type == "port":
                    port_type = input("Common or Full port scan? (C/F): ")
                    if port_type.lower() == "c":
                        common_ports = []
                        for each in self.ports_list.values():
                            for ports in each.split(','):
                                common_ports.append(ports)
                        self.scan_ports = (','.join(common_ports))
                        self.output_file = self.application + "_" + self.name + "_common_ports_raw_" + self.timestamp
                    elif port_type.lower() == "f":
                        self.scan_ports = "1-65535"
                        self.output_file = self.application + "_" + self.name + "_full_ports_raw_" + self.timestamp
                    else:
                        self.scan_settings()
                    return()
                elif self.scan_type == "ping":
                    self.output_file = self.application + "_" + self.name + "_live_hosts_raw_" + self.timestamp
                    return()
        except:
            pass

    ###################################################################################################################
    ### END SCAN SETTINGS FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### PING SWEEP FUNCTIONS ###
    ###################################################################################################################

    def ping_sweep(self):
        self.scan_type = "ping"
        try:
            target_list = self.clean_target_list_check()
            self.scan_settings()

            # Check for CIDR Notation as target
            line = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}', target_list)

            # Execute ping sweep command
            if self.application == "nmap":
                if line:
                    subprocess.call([self.application, "-e", self.interface, self.rate, "-sP", line.group(),
                                     "-oG", ("./Enumeration/" + self.output_file),
                                     "-oX", ("./xml/" + self.output_file)])
                else:
                    subprocess.call([self.application, "-e", self.interface, self.rate, "-sP", "-iL", target_list,
                                     "-oG", ("./Enumeration/" + self.output_file),
                                     "-oX", ("./xml/" + self.output_file)])
            if self.application == "masscan":
                # Execute masscan command
                if line:
                    subprocess.call([self.application, "-e", self.interface, "-p0", "--ping",
                                     line.group(), self.rate, "-oG", ("./Enumeration/" + self.output_file)])
                else:
                    subprocess.call([self.application, "-e", self.interface, "-p0", "--ping",
                                     "-iL", target_list, self.rate, "-oG", ("./Enumeration/" + self.output_file)])

            # Call the file cleaning function sending the name of the output and clean files

            self.clean(("./Enumeration/" + self.output_file), self.scan_type)

            self.main_menu()


        except OSError:
            print("File not found.  Try again...masscan_ping")
            self.ping_sweep()

    ###################################################################################################################
    ### END PING SWEEP FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### PORT SCAN FUNCTIONS ###
    ###################################################################################################################
    def port_scan(self):
        self.scan_type = "port"
        try:
            # Set options for command and output
            target_list = self.clean_target_list_check()
            self.scan_settings()
            # Check for CIDR Notation as target
            line = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}', target_list)

            print("\n------------------------------------------")
            print("Scanning Ports: " + self.scan_ports)
            # Execute masscan command
            if line:
                subprocess.call(
                    [self.application, "-e", self.interface, "-p", self.scan_ports,
                     line.group(), self.rate, "-oG", ("./Enumeration/" + self.output_file)])
            else:
                subprocess.call([self.application, "-e", self.interface, "-p", self.scan_ports,
                                 "-iL", target_list, self.rate, "-oG", ("./Enumeration/" + self.output_file)])

            self.clean(("./Enumeration/" + self.output_file), self.scan_type)

            self.main_menu()

        except OSError:
            print("File not found.  Try again...masscan_ports")
            self.port_scan()
    ###################################################################################################################
    ### END PORT SCAN FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### BANNER GRAB FUNCTIONS ###
    ###################################################################################################################
    def banner_grab(self):
        try:
            self.scan_type = "banner_grab"
            self.application = "nmap"
            self.list_directory()
            self.output_file = "nmap_banner_grab_" + self.name + "_" + self.port_number + "_" + self.timestamp

            subprocess.call(["nmap", "-sV", "-e", self.interface, "-p", self.port_number,
                             "-iL", self.target_list, "-oG", ("./Enumeration/" + self.output_file),
                             "-oX", ("./xml/" + self.output_file)])

            self.clean(("./Enumeration/" + self.output_file), self.scan_type)
            self.main_menu()

        except OSError:
            print("File not found.  Try again...nmap_ports")
            self.banner_grab()
    ###################################################################################################################
    ### END BANNER GRAB FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### EYEWITNESS FUNCTIONS ###
    ###################################################################################################################
    def eyewitness_scan(self):
        try:
            self.scan_type = "eyewitness_scan"
            self.application = "eyewitness"
            # Set options for command and output

            # Select protocol
            protocol_check = input("Use http or https?: ")
            if protocol_check.lower() != "http":
                if protocol_check.lower() != "https":
                    print("Invalid selection. Please try again.")
                    self.eyewitness_scan()
            self.list_directory()

            eyewitness_file = ("./EyeWitness_Reports/eyewitness_IP_scan_list_" +
                               self.port_number + "_" + self.timestamp)
            eyewitness_folder = ("./EyeWitness_Reports/eyewitness_" + self.name + "_report_port_" +
                                 self.port_number + "_" + self.timestamp)

            read = open(self.target_list, 'r')
            scan_list = open(eyewitness_file, 'w+')
            for each in read.readlines():
                scan_list.write(protocol_check + "://" + each.strip("\n") + ":" + self.port_number + "\n")
            read.close()
            scan_list.close()

            subprocess.call(
                ["./eyewitness/EyeWitness.py", "-f", eyewitness_file, "--headless",
                 "-d", eyewitness_folder, "--no-prompt"])

            print("Scan Complete! Report is located at " + eyewitness_folder)
            self.main_menu()
        except ValueError:
            print("Invalid entry please try again.")
            self.eyewitness_scan()
    ###################################################################################################################
    ### END EYEWITNESS FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### FILE LOADER FUNCTIONS ###
    ###################################################################################################################
    # Load Files from folders
    def load_files(self):
        self.output_files = {}
        self.clean_files = {}
        self.clean_target_list_files = {}
        self.output_file_counter = 1
        self.clean_file_counter = 1
        self.clean_target_list_counter = 1

        # Load files from the Enumeration folder
        enumeration_files = os.listdir("Enumeration")
        for each in enumeration_files:
            if "clean" in each:
                self.add_clean_files(each)
            else:
                self.add_output_files(each)

        # Load files from the clean_target_lists folder
        clean_target_list_files = os.listdir("clean_target_lists")
        for each in clean_target_list_files:
            self.add_clean_target_list(each)
        return

    ###################################################################################################################
    ### END FILE LOADER FUNCTIONS ###
    ###################################################################################################################

    ###################################################################################################################
    ### FUNCTIONS ###
    ###################################################################################################################

    def exit(self):
        close = input("Are you sure you want to quit? (y/n)")
        if close.lower() == 'y':
            sys.exit()
        elif close.lower() == 'n':
            self.main_menu()
        else:
            exit()

    ###################################################################################################################
    ### END FUNCTIONS ###
    ###################################################################################################################

# Main Program
if __name__ == "__main__":
    # Launch main menu
    try:
        if os.path.isdir('./Day1') == False:
            os.mkdir('./Day1')
        if os.path.isdir('./Day1/Enumeration') == False:
            os.mkdir('./Day1/Enumeration')
        if os.path.isdir('./Day1/Hosts') == False:
            os.mkdir('./Day1/Hosts')
        if os.path.isdir('./Day1/clean_target_lists') == False:
            os.mkdir('./Day1/clean_target_lists')
        if os.path.isdir('./Day1/EyeWitness_Reports') == False:
            os.mkdir('./Day1/EyeWitness_Reports')
        if os.path.isdir('./Day1/xml') == False:
            os.mkdir('./Day1/xml')
        project = Day_One(input('Input site name:'))
        project.interface = input('Enter network interface: ')
        os.chdir('./Day1')
        project.load_files()
        project.main_menu()
        # Set interface option
    except KeyboardInterrupt:
        print("\n")
        exit()
