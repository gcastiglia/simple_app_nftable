import json
from nftables import Nftables
import sys
import subprocess
import re



def init_fw():
    commande_init = {
    "nftables": [
    { "flush": { "ruleset": None } },
    { "add": { "table": { "family": "inet", "name": "firewall" } } },
    { "add": { "set": { "family": "inet", "name": "blacklist", "table": "firewall", "type": "ipv4_addr", "flags": ["interval"]} } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "input","type":"filter","hook":"input","prio":0,"policy":"drop" } } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "forward", "type":"filter","hook":"forward","prio":0,"policy":"drop"} } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "nat", "type":"nat","hook":"postrouting","prio":0,"policy":"accept"} } },
    { "add": { "chain": { "family": "inet", "table": "firewall", "name": "prerouting", "type":"filter","hook":"prerouting","prio":-300,"policy":"accept"} } },
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "nat",
                         "expr": [ { "match": { "op": "==", "left": { "meta": { "key": "oifname"} }, "right": "enp1s0" } },
                                   { "masquerade": None } ] } } },
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                         "expr": [ { "match": { "op": "==", "left": { "meta": { "key": "iif"} }, "right": "lo" } },
                                   { "accept": None } ] } } },                                   
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "==", "left": {"ct": {"key":"state"}}, "right": {"set": ["established", "related"]}}},
                                 {"accept": None}]}}},                               
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "in", "left": {"ct": {"key":"state"}}, "right": "invalid"}},
                                 {"drop": None}]}}},
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "forward",
                        "expr": [{"match": {"op": "==", "left": {"ct": {"key":"state"}}, "right": {"set": ["established", "related"]}}},
                                 {"accept": None}]}}},                               
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "forward",
                        "expr": [{"match": {"op": "in", "left": {"ct": {"key":"state"}}, "right": "invalid"}},
                                 {"drop": None}]}}},
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "==", "left": {"meta": {"key":"l4proto"}}, "right": "icmp"}},
                                 {"accept": None}]}}},                                                                                                      
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "input",
                        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": {"set" : ["5000","22"]}}},
                                 {"accept": None}]}}},
    { "add": { "rule": { "family": "inet", "table": "firewall", "chain": "prerouting",
                        "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@blacklist"}},
                                 {"drop": None}]}}}                             
    ]
    }
    ruleset_json = configure_nftable(commande_init)


def get_network_interfaces():
    json_dmp = manipuler_resultat()
    nat_rule = avoir_rule(json_dmp,"rule")
    nat_rule = recup_nat_rule(nat_rule)
    int_to_nat = nat_rule[0]["rule"]["expr"][0]["match"]["right"]
    print(int_to_nat)
    try:    
        liste_interface = []
        schema_interface = {"name":"oui","ip_address":"lol","status":"oui","to_wan":"non"}
        result = subprocess.run(['ip', 'a'], capture_output=True, text=True)
        lines = result.stdout.split('\n')
    #print(lines)
        for line in lines:
            if("mtu" in line):
                interface = line.split(":")[1]
                print(interface)
                if int_to_nat in interface:
                    to_wan = "oui"
                else:
                    to_wan = "non"    
                statut = line.split(":")[2].split()[6]
            if("inet " in line):
                ip = line.split(" ")[5]
                schema_interface = {"name":interface,"ip_address":ip,"status":statut,"to_wan":to_wan}
                liste_interface.append(schema_interface)
    #print(liste_interface)               
        return liste_interface
    except Exception as e:
        print(f"❌ Exception: {e}")
        return {"name":"erreur","ip_address":"erreur","status":"erreur","to_wan":"non"}                    


#####

def manipuler_resultat():
    nft = Nftables()
    nft.set_json_output(True)
    
    cmd = {
        "nftables": [
            {"list": {"ruleset": None}}
        ]
    }
    json_cmd = json.loads(json.dumps(cmd))
    rc, output, error = nft.json_cmd(json_cmd)
    if rc == 0:
        #print("\n📋 Règles actuelles:")
        json_dmp = json.loads(json.dumps(output))
        return json_dmp
    else:
        print(f"❌ Erreur: {error}")
        sys.exit(1)   

def separer_rule_list(json_dmp):
    liste_exploitable = json_dmp["nftables"]
    liste_finale = []
    def get_chain(element):
        return "chain" in element   
    chaines = list(filter(get_chain,liste_exploitable))
    def get_rule(element):
        return "rule" in element   
    rules = list(filter(get_rule,liste_exploitable))
    def get_table(element):
        return "table" in element
    tables = list(filter(get_table,liste_exploitable))
    def get_set(element):
        return "set" in element
    sets = list(filter(get_set,liste_exploitable))    
    liste_finale.append(tables)
    liste_finale.append(sets)
    liste_finale.append(chaines)
    liste_finale.append(rules)                            
    return liste_finale  



def set_port(liste_protocole):
    if len(liste_protocole) == 0:
        return liste_protocole[0]
    else:
        return {"set":liste_protocole}

def set_ip(liste_ip):
    def traite_ip(ip):
        if "/" in ip:
            addr,len = ip.split("/")
            return { "prefix" : {"addr" : addr, "len": int(len) } }
        else:
            return ip
    retour = list(map(traite_ip,liste_ip))
    return {"set": retour}


def set_reverse_ip(json_ip):
    def traite_ip(ip):
        if "prefix" in ip:
            ip_str = ""
            
            ip_str = "{0}/{1}".format(ip["prefix"]["addr"],ip["prefix"]["len"])
            return ip_str
        else:
            return ip
    retour = list(map(traite_ip,json_ip))
    return retour



def avoir_rule(json_dmp,choix):
    sous_ensemble = {}
    liste_rule = separer_rule_list(json_dmp)
    if choix == "table":
        sous_ensemble = liste_rule[0]
    elif choix == "set":
        sous_ensemble = liste_rule[1]
    elif choix == "chaine":
        sous_ensemble = liste_rule[2]          
    elif choix == "rule":
        sous_ensemble = liste_rule[3]
    elif choix == "tout":
        sous_ensemble = liste_rule
    return sous_ensemble


def recup_input_rule(liste_filter):
    def recup_chain(rule):
        value = "input"
        return value in rule["rule"].values()
    return list(filter(recup_chain,liste_filter))


def recup_nat_rule(liste_filter):
    def recup_chain(rule):
        value = "nat"
        return value in rule["rule"].values()
    return list(filter(recup_chain,liste_filter))

def recup_forward_rule(liste_filter):
    def recup_chain(rule):
        value = "forward"
        return value in rule["rule"].values()
    return list(filter(recup_chain,liste_filter))

def recup_routing_lan(liste_filter):
    liste_return = []
    liste_forward = recup_forward_rule(liste_filter)
    for rule in liste_forward:
        if "oifname" in json.dumps(rule):
            1
        else:
            liste_return.append(rule)
    return liste_return            



def format_set_value(right_value):
    """Formate la valeur right en gérant les sets et les préfixes"""
    if isinstance(right_value, dict) and 'set' in right_value:
        set_values = right_value['set']
        formatted_values = []
        for val in set_values:
            if isinstance(val, dict) and 'prefix' in val:
                # Gérer le préfixe IP (ex: 192.168.59.0/24)
                prefix = val['prefix']
                formatted_values.append(f"{prefix['addr']}/{prefix['len']}")
            else:
                formatted_values.append(str(val))
        return formatted_values
    elif isinstance(right_value, dict) and 'prefix' in right_value:
        # Cas où right est directement un préfixe
        prefix = right_value['prefix']
        return [f"{prefix['addr']}/{prefix['len']}"]
    elif isinstance(right_value, list):
        return [str(val) for val in right_value]
    else:
        return [str(right_value)]

def parse_rules(data):
    result = []
    
    # Gérer le cas où data est une liste directe de règles
    if isinstance(data, list):
        rules_list = data
    # Gérer le cas où data est dans un format nftables
    elif isinstance(data, dict) and 'nftables' in data:
        rules_list = []
        for nft_entry in data['nftables']:
            if 'add' in nft_entry and 'rule' in nft_entry['add']:
                rules_list.append({'rule': nft_entry['add']['rule']})
    else:
        return result
    
    for item in rules_list:
        rule = item['rule']
        handle = rule.get('handle', None)
        
        # Trouver l'action (accept ou drop)
        action = None
        match_infos = []
        
        for expr in rule['expr']:
            if 'accept' in expr:
                action = 'accept'
            elif 'drop' in expr:
                action = 'drop'
            elif 'match' in expr:
                match_infos.append(expr['match'])
        
        # Initialiser l'entrée de résultat
        entry = {
            'handle': handle,
            'action': action,
            'type': 'input',  # valeur par défaut
            
        }
        
        # Variables pour stocker les informations de match
        match_parts = []
        
        # Traiter les informations de match
        for match_info in match_infos:
            left = match_info['left']
            right = match_info['right']
            
            # Vérifier si c'est meta ou ct
            if 'meta' in left:
                entry['type'] = 'meta'
                key = left['meta']['key']
                values = format_set_value(right)
                match_parts.append(f"meta {key} {', '.join(values)}")
            elif 'ct' in left:
                entry['type'] = 'ct'
                key = left['ct']['key']
                values = format_set_value(right)
                match_parts.append(f"ct {key} {', '.join(values)}")
            elif 'payload' in left:
                protocol = left['payload'].get('protocol', '')
                field = left['payload'].get('field', '')
                values = format_set_value(right)
                
                # Cas spécial pour les adresses IP sources
                if field == 'saddr':
                    entry['ip_source'] = ', '.join(values)
                    #match_parts.append(f"ip saddr {entry['ip_source']}")
                    if entry['type'] == 'input':
                        entry['type'] = 'payload'
                # Cas pour les ports
                elif field == 'dport' or field == 'sport':
                    entry['protocol'] = protocol
                    entry['port'] = ', '.join(values)
                    #match_parts.append(f"{protocol} {field} {entry['port']}")
                    if entry['type'] == 'input':
                        entry['type'] = 'payload'
                else:
                    if entry['type'] == 'input':
                        entry['type'] = 'payload'
                    #match_parts.append(f"{protocol} {field} {', '.join(values)}")
        
        # Construire le champ match final
        if match_parts:
            entry['match'] = ' | '.join(match_parts)
        
        result.append(entry)
    
    return result




def get_input_rule():
    """Affiche les règles actuelles"""
    json_dmp = manipuler_resultat()
    rules = avoir_rule(json_dmp,"rule")
    rules = recup_input_rule(rules)
    #print(parse_rules(rules))
    return parse_rules(rules)  



def ajout_input_regle(ip,protocol,port):
    if ip == "":
        ruleset_input_tcp_udp = { "nftables" : [{
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "input",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": port}},
                            {"accept": None}
                        ]
                    }
                }}]       
            }
        return ruleset_input_tcp_udp
    else:
        ruleset_input_spec_ip_tcp_udp = { "nftables" : [{
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "input",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": set_ip([ip])}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": port}},
                            {"accept": None}
                        ]
                    }
            }}]    
        }
        return ruleset_input_spec_ip_tcp_udp       



def get_blacklist():
    json_dmp = manipuler_resultat()
    try:
        set_ip = avoir_rule(json_dmp,"set")
        liste_ip = set_reverse_ip(set_ip[0]["set"]["elem"])
    except:
        return [{"num":-1,"ip":""}]    
    rtr_ip = []
    count = 0
    for ip in liste_ip:
        rtr_ip.append({"num":count,"ip":ip})
        count += 1
    return rtr_ip    
    


def ajout_blacklist(ip):
    ruleset_add = {"nftables" : [
        {
            "add" : {
                "element" : {
                    "family" : "inet",
                    "table": "firewall",
                    "name": "blacklist",
                    "elem": set_ip([ip])["set"]                
                    }
                }
            }
        ]
    }
    etat = configure_nftable(ruleset_add)
    return etat    
    

def suppr_blacklist(count):
    ip_blacklist = get_blacklist()[count]["ip"]
    ruleset_delete = {"nftables" : [
        {
            "delete" : {
                "element" : {
                    "family" : "inet",
                    "table": "firewall",
                    "name": "blacklist",
                    "elem": set_ip([ip_blacklist])["set"]                
                    }
                }
            }
        ]
    }
    etat = configure_nftable(ruleset_delete)
    return etat    
         





def delete_nft_rule(handle,chain):    
    ruleset_delete = {"nftables" : [
        {
            "delete" : {
                "rule" : {
                    "chain" : chain,
                    "family" : "inet",
                    "table": "firewall",
                    "handle": handle
                    
                    }
                }
            }
        ]
    }
    etat = configure_nftable(ruleset_delete)
    return etat




def configure_nftable(json_dump):  
    nft = Nftables()
    nft.set_json_output(True)
    try:
        # Convertir en JSON et appliquer
        # print("On ne peut qu'ajouter des regles dukou :D")
        ruleset_json = json.dumps(json_dump)
        print(ruleset_json)
        ruleset_json = json.loads(ruleset_json)
        rc, output, error = nft.json_cmd(ruleset_json)
        if rc != 0:
            print(f"❌ Erreur lors de l'application des règles: {error}")
            return False
        else:
            print("✅ Règles nftables appliquées avec succès!")
            print(f"📋 Sortie: {output}")
            return True        
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False


def get_wan_rule():
    """Affiche les wan"""
    json_dmp = manipuler_resultat()
    rules = avoir_rule(json_dmp,"rule")
    liste_to_wan = []
    ip_to_wan = []
    rules = recup_forward_rule(rules)
    for rule in rules:
        if "oifname" in json.dumps(rule):
            liste_to_wan.append(rule)        
    for rule in liste_to_wan:
        schema = {"handle" : "","ip_source":""}
        schema["handle"] = rule["rule"]["handle"]
        if "set" in rule["rule"]["expr"][0]["match"]["right"]:
            schema["ip_source"] = ", ".join(set_reverse_ip(rule["rule"]["expr"][0]["match"]["right"]["set"]))
        else:
            print(rule["rule"]["expr"][0]["match"]["right"])
            schema["ip_source"] = rule["rule"]["expr"][0]["match"]["right"]
        ip_to_wan.append(schema)    
    return ip_to_wan              
    


def ajout_to_wan(ip):
    ruleset_forward_wan = {"nftables" : [
        {
            "add" : {
                "rule" : {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "forward",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": set_ip([ip])}},
                            {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "enp1s0" }},
                            {"accept": None}
                        ]                
                    }
                }
            }
        ]
    }
    etat = configure_nftable(ruleset_forward_wan)
    return etat





def parse_forward_rules(data):
    result = []
    
    # Gérer le cas où data est une liste directe de règles
    if isinstance(data, list):
        rules_list = data
    # Gérer le cas où data est dans un format nftables
    elif isinstance(data, dict) and 'nftables' in data:
        rules_list = []
        for nft_entry in data['nftables']:
            if 'add' in nft_entry and 'rule' in nft_entry['add']:
                rules_list.append({'rule': nft_entry['add']['rule']})
    else:
        return result
    
    for item in rules_list:
        rule = item['rule']
        handle = rule.get('handle', None)
        
        # Trouver l'action (accept ou drop)
        action = None
        
        for expr in rule['expr']:
            if 'accept' in expr:
                action = 'accept'
            elif 'drop' in expr:
                action = 'drop'
        
        # Initialiser l'entrée de résultat
        entry = {
            'handle': handle,
            'action': action,
            'type': 'input',  # valeur par défaut
        }
        
        # Variables pour stocker les informations
        ct_parts = []
        ip_source = None
        ip_dest = None
        protocol = None
        port = None
        icmp_type = None
        
        # Parcourir toutes les expressions
        for expr in rule['expr']:
            if 'match' in expr:
                match_info = expr['match']
                left = match_info.get('left', {})
                right = match_info.get('right', {})
                
                # === GESTION CT (connection tracking) ===
                if 'ct' in left:
                    entry['type'] = 'ct'
                    key = left['ct']['key']
                    values = format_set_value(right)
                    # Format: "ct state established, related"
                    ct_parts.append(f"ct {key} {', '.join(values)}")
                
                # === GESTION PAYLOAD ===
                elif 'payload' in left:
                    entry['type'] = 'payload'
                    payload = left['payload']
                    protocol_field = payload.get('protocol', '')
                    field = payload.get('field', '')
                    values = format_set_value(right)
                    
                    # IP source (saddr)
                    if field == 'saddr':
                        ip_source = ', '.join(values)
                        protocol = 'ip'
                    
                    # IP destination (daddr)
                    elif field == 'daddr':
                        ip_dest = ', '.join(values)
                        protocol = 'ip'
                    
                    # Port destination (dport) ou port source (sport)
                    elif field == 'dport' or field == 'sport':
                        protocol = protocol_field
                        port = ', '.join(values)
                    
                    # ICMP type
                    elif field == 'type' and protocol_field == 'icmp':
                        protocol = 'icmp'
                        
        
        # === CONSTRUCTION DES ENTRÉES ===
        
        # Pour CT (connection tracking)
        if entry['type'] == 'ct':
            entry['match'] = ' | '.join(ct_parts)
        
        # Pour PAYLOAD (règles de routage)
        elif entry['type'] == 'payload':
            # Ajouter les champs spécifiques payload
            if ip_source:
                entry['ip_source'] = ip_source
            if ip_dest:
                entry['ip_destination'] = ip_dest
            if protocol:
                entry['protocol'] = protocol
            if port:
                entry['port'] = port
            
            # Si c'est ICMP, ajouter le type vide comme "port"
            if protocol == 'icmp' and icmp_type:
                entry['port'] = ""
        
        result.append(entry)
    
    return result



def get_forward_rule():
    """Affiche les règles actuelles"""
    json_dmp = manipuler_resultat()
    rules = avoir_rule(json_dmp,"rule")
    rules = recup_routing_lan(rules)
    print(rules)
    #print(parse_forward_rules(rules))
    return parse_forward_rules(rules)



def ajout_routing_rule(ip_source,ip_dest,protocol,port):
    if port == -1:
        ruleset_forward_ping = { "nftables" : [{
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "forward",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": set_ip([ip_source])}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": set_ip([ip_dest])}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "icmp", "field": "type"}}, "right": {"set" : ["echo-reply","echo-request"] }}},
                            {"accept": None}
                        ]
                    }
                }
            }]   
        }
        return ruleset_forward_ping
    else:
        ruleset_forward_tcp_udp = { "nftables" : [{
                "add": {
                    "rule": {
                        "family": "inet",
                        "table": "firewall",
                        "chain": "forward",
                        "expr": [
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": set_ip([ip_source])}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": set_ip([ip_dest])}},
                            {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": set_port([port])}},
                            {"accept": None}
                        ]
                    }
                }    
            }]
        }
        return ruleset_forward_tcp_udp    
            
            




def configure_input(ip,protocol,port):
    ajout_in_regle = ajout_input_regle(ip,protocol,port)
    ruleset_json = configure_nftable(ajout_in_regle)


def configure_routing(ip_source,ip_dest,protocol,port):
    ajout_route_regle = ajout_routing_rule(ip_source,ip_dest,protocol,port)
    ruleset_json = configure_nftable(ajout_route_regle)


def add_wan(ip):
    ajout_wan = ajout_to_wan(ip)
    ruleset_json = configure_nftable(ajout_wan)


def add_bl(ip):
    ajout_bl = ajout_blacklist(ip)
    ruleset_json = configure_nftable(ajout_bl)
    

def del_bl(count):
    delete = suppr_blacklist(count)
    ruleset_json = configure_nftable(delete)
    


