import shodan
import json
import sys
import requests
with open('config.json') as f:
    data = json.load(f)

api_key = data['api']
api = shodan.Shodan(api_key)



def get_ip():
    try:
        req = requests.get('https://api.ipify.org?format=json')
        ip_json = req.json()
        
        return ip_json['ip']
    except:
        print("There was an error! Probably a connection error")
        sys.exit()

def scan_host(host_ip):
    host = api.host(host_ip)
    #print(host)
    port_info = {}
    for block in host['data']:
        port_info[block['port']] = block['product']
    return {
        "hostnames": str(host['hostnames']),
        "city": host['data'][0]['location']['city'],
        "country_name": host['country_name'],
        "org": host['data'][0]['org'],
        "ports": len(host['ports']),
        "port_info": port_info
    }

def shodan_search(query):
    host = api.search(query)
    if len(host['matches']) == 0:
        print("No matches!")
    else:
        for match in host['matches']:
            print("--------------------------")
            print("IP: " + match['ip_str'])
            print("Port: " + str(match['port']))
            print("Org: " + match['org'])
            print("Hostname(s): " + str(match['hostnames']))
            print("--------------------------")



def main():
    exit_door = False
    while not exit_door:
        print("""
        1.) What's my IP
        2.) Scan a host
        3.) Shodan search
        0.) Exit
        """)
        choice = input("Pick: ")
        
        if not choice.isdigit():
            print("Not a number")
            sys.exit()
        number = int(choice)
        
        if number == 0:
            exit_door = True
        elif number == 1:
            ip = get_ip()
            print("Your IP is {}".format(ip))
            res = input("Would you like to quit? (y/n): ")
            if res.lower() == "y":
                exit_door = True
            elif res.lower() == 'n':
                continue
            else:
                print("Invalid response, I'm quitting anyways")
                exit_door = True
        elif number == 2:
            res = input("Host IP: ")
            info = scan_host(res)
            print("---------------------")
            print("Hostname: " + info['hostnames'])
            print("Country: " + info['country_name'])
            print("City: " + info['city'])
            print("Organization: " + info['org'])
            print("Total ports: " + str(info['ports']))
            print("\n")
            print("Ports")
            for k,v in info['port_info'].items():
                print(k, v)
            print("---------------------")
        elif number == 3:
            res = input("Query: ")
            shodan_search(res)

if __name__ == "__main__":
    main()