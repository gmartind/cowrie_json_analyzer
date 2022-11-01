#!/usr/bin/env python3
from urllib.request import urlopen

import sys
import json
import requests
f = open('cowrie.json.2022-10-29', 'r')

full_log = [json.loads(line) for line in f]


#TOP IPS
def showIPs():
        session_connect_log = [x for x in full_log if x['eventid'] == 'cowrie.session.connect']

        ips_dict = {}
        values = 0

        for line in session_connect_log:
                if line['src_ip'] in ips_dict.keys():
                        ips_dict[line['src_ip']] += 1
                else:
                        ips_dict[line['src_ip']] = 1
                        values += 1


        top_connection_ips = []
        ips_dict_aux = ips_dict.copy()

        for i in range(values):
                top1 = max(ips_dict_aux, key=ips_dict_aux.get)
                tuple = top1, int(ips_dict_aux[top1])
                top_connection_ips.append(tuple)
                ips_dict_aux.pop(top1)

        print("")
        print("       TOP source IP Addresses")
        print("-----------------------------------------------------")
        print(str(len(session_connect_log)) + " connection attempts.")

        i = 0
        while i < len(ips_dict) and i < 10:
                print(str(i + 1) + ". " + str(top_connection_ips[i][0]))
                print("  -> " + str(round(top_connection_ips[i][1] / len(session_connect_log) * 100,2)) + "%", end=' ')
                query = "http://ip-api.com/json/" + top_connection_ips[i][0]
                response = urlopen(query)
                ip_json = json.loads(response.read())
                print("  -> " + ip_json['country'])
                i += 1

        print("")
##########################
#TOP ATTEMTPED USERNAMES, TOP ATTEMPTED PASSWORDS AND TOP ATTEMPTED USERNAME AND PASSWORD COMBO
def common_attempted_up():
        usernames_and_passwords_log = [x for x in full_log if x['eventid'] == 'cowrie.login.failed' or x['eventid'] == 'cowrie.logi>        usernames_dict = {}
        passwords_dict = {}
        combo_dict ={}
        u_values = 0
        p_values = 0
                c_values = 0
        for line in usernames_and_passwords_log:
                if line['username'] in usernames_dict.keys():
                        usernames_dict[line['username']] += 1
                else:
                        usernames_dict[line['username']] = 1
                        u_values += 1
                if line['password'] in passwords_dict.keys():
                        passwords_dict[line['password']] += 1
                else:
                        passwords_dict[line['password']] = 1
                        p_values += 1

                tuple = line['username'], line['password']
                if tuple in combo_dict:
                        combo_dict[tuple] += 1
                else:
                        combo_dict[tuple] = 1
                        c_values += 1

        top_usernames = []
        usernames_dict_aux = usernames_dict.copy()

        for i in range(u_values):
                top1 = max(usernames_dict_aux, key=usernames_dict_aux.get)
                tuple = top1, int(usernames_dict_aux[top1])
                top_usernames.append(tuple)
                usernames_dict_aux.pop(top1)

        print(" ")
        print("       TOP attempted usernames")
        print("-----------------------------------------------------")
        print(str(len(usernames_dict)) + " different usernames")

        i = 0
        while i < len(usernames_dict) and i < 10:
                print(str(i + 1) + ". '" + str(top_usernames[i][0]) +"'")
                print("  -> " + str(round(top_usernames[i][1] / len(usernames_and_passwords_log) * 100,2)) + "% of username attempt>                i += 1

        top_passwords = []
        passwords_dict_aux = passwords_dict.copy()

        for i in range(p_values):
                top1 = max(passwords_dict_aux, key=passwords_dict_aux.get)
                tuple = top1, int(passwords_dict_aux[top1])
                top_passwords.append(tuple)
                passwords_dict_aux.pop(top1)

        print(" ")
        print("       TOP attempted passwords")
        print("-----------------------------------------------------")

        i = 0
        while i < len(passwords_dict) and i < 10:
                print(str(i + 1) + ". '" + str(top_passwords[i][0]) +"'")
                print("  -> " + str(round(top_passwords[i][1] / len(usernames_and_passwords_log) * 100,2)) + "% of passwords attemp>                i += 1

        print(" ")
        
        top_combos = []
        combo_dict_aux = combo_dict.copy()

        for i in range(c_values):
                top1 = max(combo_dict_aux, key=combo_dict_aux.get)
                tuple = top1, int(combo_dict_aux[top1])
                top_combos.append(tuple)
                combo_dict_aux.pop(top1)

        print(" ")
        print("       TOP attempted username & password pairs")
        print("-----------------------------------------------------")
        i = 0
        while i < len(combo_dict) and i < 10:
                print(str(i + 1) + ". '" + str(top_combos[i][0]) + "'")
                print("  -> " + str(round(top_combos[i][1] / len(usernames_and_passwords_log) * 100,2)) + "% of username and passwo>                i += 1
        print("")
if len(sys.argv) == 1:
        showIPs()
        common_attempted_up()
else:
        if sys.argv[1] == 'top-ips':
                showIPs()
        elif sys.argv[1] == 'top-users':
                common_attempted_up()
        else:
                showIPs()
                common_attempted_up()

