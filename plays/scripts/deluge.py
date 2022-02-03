from argparse import Action
from email.quoprimime import body_check
import json, random
from os import access
from unittest import result
import requests

def create_session(deluge_scheme: str, deluge_hostname: str, deluge_port: int, deluge_path: str, deluge_password: str, validate_certs=False, id: int=0):
    session = requests.Session()
    
    login_json = { \
        "id" : id,
        "method": "auth.login",
        "params": [deluge_password]
    }

    api_url = deluge_scheme + "://" + deluge_hostname + ":" + str(deluge_port) + "/deluge/json"
    response = session.post(api_url, json=login_json, verify=validate_certs)

    json_response = response.json()
    if json_response is not None:
        if 'result' in json_response and json_response["result"]:
            return session, api_url
    
    return None


def get_deluged_hosts(deluge_session: requests.Session, api_url: str, id: int, validate_certs=False):
    body = { \
        "method": "web.get_hosts",
        "params": [],
        "id": id
    }
    deluge_host_json = deluge_session.post(api_url,json=body, verify=validate_certs)
    return deluge_host_json.json()

def connect_to_deluged_host(deluge_session: requests.Session, api_url: str, hostid: str, id: int, validate_certs=False):
    body = { \
        "method": "web.connect",
        "params": [hostid],
        "id": id
    }
    response = deluge_session.post(api_url, json=body, verify=validate_certs)
    return 'result' in response.json() and response.json()["result"]

def enable_plugin(deluge_session: requests.Session, api_url: str, plugin: str, id: int, validate_certs=False):
    body = { \
        "method": "core.enable_plugin",
        "params": [plugin],
        "id": id
    }
    response = deluge_session.post(api_url, json=body, verify=validate_certs)
    return 'result' in response.json() and response.json()["result"]

def add_on_add_execute_command(deluge_session: requests.Session, api_url: str, trigger: str, command: str, id: int, validate_certs=False):
    
    get_body = { \
        "method": "execute.get_commands",
        "params": [],
        "id": id
    }

    response = deluge_session.post(api_url, json=get_body, verify=validate_certs).json()
    for action in response["result"]:
        deluge_trigger = action[1]
        deluge_action = action[2]
        if deluge_trigger == trigger and deluge_action == command:
            return
    
    body = { \
        "method": "execute.add_command",
        "params": [trigger, command],
        "id": id
    }
    response = deluge_session.post(api_url, json=body, verify=validate_certs)
    return 'result' in response.json() and response.json()["result"]

def get_torrent_ids(deluge_session: requests.Session, api_url: str, id: int, validate_certs=False):
    body = { \
        "method": "core.get_torrents_status",
        "params": [[], []],
        "id": id
    }
    response = deluge_session.post(api_url, json=body, verify=validate_certs)
    return 'result' in response.json() and response.json()["result"]

def append_trackers(deluge_session: requests.Session, api_url: str, torrent_id: str, trackers: list, id: int, validate_certs=False):
    body = {
        "method": "core.get_torrent_status", 
        "params": [torrent_id, "trackers"],
        "id": id
    }

    tracker_dicts = []

    torrent_json = deluge_session.post(api_url, json=body, verify=validate_certs).json()
    for tracker in torrent_json["trackers"]:
        tracker_dicts.append({"url": tracker["url"], "tier": tracker["tier"]})

    for item in trackers:
        for torrent in tracker_dicts:
            
    


id = random.randint(0,100)

session, url = create_session("https", "10.0.0.214", 443, "/deluge", "deluge")
hosts = get_deluged_hosts(session, url, id)
connect_to_deluged_host(session, url, hosts["result"][0][0], id=id)
enable_plugin(session, url, "Label", id)
enable_plugin(session, url, "Execute", id)
add_on_add_execute_command(session, url, "added", "echo hostname", id)
get_torrent_ids(session, url, id)




