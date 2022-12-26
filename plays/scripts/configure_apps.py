import threading
import requests, json, argparse, os


import urllib3

urllib3.disable_warnings()


def api_request_darr(hostname: str, port: int, path: str, api_key: str, json: dict, scheme: str="https", method: str="POST", verify_certificate=False):
    uri = scheme + "://" + hostname + ":" + str(port) + path + "?apikey=" + api_key

    response = None
    if method == "POST":
        if json is not None and isinstance(json, dict):
            response = requests.post(uri,json=json, verify=verify_certificate)
        else:
            response = requests.post(uri, verify=verify_certificate)
    elif method == "GET":
        if json is not None and isinstance(json, dict):
            response = requests.get(uri, json=json, verify=verify_certificate)
        else:
            response = requests.get(uri, verify=verify_certificate)
    
    return response

def add_torznab_indexer(hostname: str, port: int, base_uri_client: str, base_uri_indexer: str ,name: str, api_path: str, categories: list, api_key: str, scheme: str="https", custom_fields: dict=None, indexer_api_path: str="/api/v3/indexer", info_link: str=None):
    json_body = {}
    json_body.update({"configContract" : "TorznabSettings", "enableAutomaticSearch" : True, "enableInteractiveSearch": True, "enableRss" : True, "implementation" : "Torznab", "implementationName" : "Torznab", "name": name, "priority" : 25, "protocol" : "torrent", "supportsRss" : True, "supportsSearch" : True, "tags": []})
    if info_link is not None:
        json_body.update({"infoLink" : info_link})

    fields = []
    fields.append({"name" : "baseUrl", "value":  base_uri_indexer})
    fields.append({"name" :"apiPath", "value" : api_path})
    fields.append({"name" :"apiKey", "value" : api_key})
    fields.append({"name" :"categories", "value" : categories})
    fields.append({"name" :"animeCategories", "value" : []})
    fields.append({"name" :"minimumSeeders", "value" : 1})
    fields.append({"name" :"additionalParameters"})
    fields.append({"name" :"seedCriteria.seedRatio"})
    fields.append({"name" :"seedCriteria.seedTime"})
    fields.append({"name" :"seedCriteria.seasonPackSeedTime"})

    if custom_fields is not None:
        for key, value in custom_fields.items():
            if value is None:
                fields.append({"name" : key})
            else:
                fields.append({'name' : key, "value" : value})
                    
    
    json_body["fields"] = fields

    print(api_request_darr(hostname, port, base_uri_client + indexer_api_path, api_key, json=json_body, method="POST",scheme=scheme).text)




### OMBI Methods

class ombi_instance:
    def __init__(self, hostname: str, port: int, path: str, api_key:str, scheme: str="https", validate_certificates: bool=False):
        self.hostname = hostname
        self.port = port
        self.path = path
        self.scheme = scheme
        self.api_key = api_key
        self.validate_certificates = validate_certificates

def ombi_api_request(ombi: ombi_instance, api_path: str, method: str="POST", body: dict=None):
    url = ombi.scheme + "://" + ombi.hostname + ":" + str(ombi.port) + ombi.path + api_path

    api_header = {"ApiKey" : ombi.api_key, "Content-Type" : "application/json"}

    response = None
    if method == "POST":
        if body is not None:
            response = requests.post(url, data=body,verify=ombi.validate_certificates, headers=api_header)
        else:
            response = requests.post(url,verify=ombi.validate_certificates, headers=api_header)
    elif method == "GET":
        if body is not None:
            response = requests.get(url, data=body,verify=ombi.validate_certificates, headers=api_header)
        else:
            response = requests.get(url,verify=ombi.validate_certificates, headers=api_header)
    return response
    


def get_ombi_plex_token(hostname: str, port: int, path: str, plex_username: str, plex_password: str, scheme: str="https", validate_certificates: bool=False):
    json_body = {}
    json_body["login"] = plex_username
    json_body["password"] = plex_password

    
    uri = scheme + "://" + hostname + ":" + str(port) + path + "/api/v1/Plex/"
    response = requests.post(uri, data=json.dumps(json_body), verify=validate_certificates, headers={"content-type" : "application/json"})
    return response.json()['user']['authentication_token']

def post_ombi_plex_token(hostname: str, port: int, path: str, scheme: str="https", validate_certificates: bool=False):
    fields = {"password": "",
    "usePlexAdminAccount": True,
    "username": ""
    }

    uri = scheme + "://" + hostname + ":" + str(port) + path + "/api/v1/Identity/Wizard/"
    response = requests.post(uri, data=json.dumps(fields), verify=validate_certificates, headers={"content-type" : "application/json"})

    login_results = response.json()
    return login_results["result"]

def set_ombi_app_config(hostname: str, port: int, path: str, scheme: str="https", validate_certificates: bool=False):
    fields = {"applicationName": "Ombi - nasinabox",
    "applicationUrl": None,
    "logo": None
    }

    uri = scheme + "://" + hostname + ":" + str(port) + path + "/api/v2/wizard/config"
    response = requests.post(uri, data=json.dumps(fields), verify=validate_certificates, headers={"content-type" : "application/json"})

    login_results = response.json()
    return login_results["applicationName"]


def ombi_get_quality_profiles_from_sonarr(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfiles" : 0, "port" : str(sonarr_port), "qualityProfile" : None, "qualityProfileAnime" : None, "rootPath" : None, "rootPathAnime" : None, "seasonFolders" : False, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "/api/v1/Sonarr/Profiles/", body=json.dumps(fields))
    final_names = []
    for profile in response.json():
        final_names.append((profile['id'], profile['name']))
    return final_names

def ombi_get_root_dirs_from_sonarr(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfiles" : 0, "port" : str(sonarr_port), "qualityProfile" : None, "qualityProfileAnime" : None, "rootPath" : None, "rootPathAnime" : None, "seasonFolders" : False, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "/api/v1/Sonarr/RootFolders", body=json.dumps(fields))
    final_names = []
    for profile in response.json():
        final_names.append((profile['id'], profile['path']))
    return final_names

def ombi_get_lang_profiles_from_sonarr(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfiles" : 0, "port" : str(sonarr_port), "qualityProfile" : None, "qualityProfileAnime" : None, "rootPath" : None, "rootPathAnime" : None, "seasonFolders" : False, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "/api/v1/Sonarr/v3/languageprofiles", body=json.dumps(fields))
    final_names = []
    for profile in response.json():
        final_names.append((profile['id'], profile['name']))
    return final_names

def ombi_upload_sonarr_profiles(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str, quality_profile: int, root_dir: int, language_profile: int, language_profile_anime: int):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfile" : language_profile, "languageProfileAnime" : language_profile_anime,"port" : str(sonarr_port), "qualityProfile" : quality_profile, "qualityProfileAnime" : quality_profile, "rootPath" : root_dir, "rootPathAnime" : root_dir, "seasonFolders" : True, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "/api/v1/Settings/Sonarr", body=json.dumps(fields))
    print(response.text)

def ombi_upload_radarr_profiles(ombi: ombi_instance, radarr_hostname: str, radarr_port: int, radarr_api_key: str, ssl: bool, base_url: str, quality_profile: int, root_dir: str):
    fields = {"radarr":{"enabled":True,"apiKey":radarr_api_key,"defaultQualityProfile":quality_profile,"defaultRootPath":root_dir,"ssl":ssl,"subDir":base_url,"ip":radarr_hostname,"port":radarr_port,"addOnly":False,"minimumAvailability":"Released","scanForAvailability":False},"radarr4K":{"enabled":False,"apiKey":radarr_api_key,"defaultQualityProfile":0,"defaultRootPath":root_dir,"ssl":ssl,"subDir":None,"ip":radarr_hostname,"port":radarr_port,"addOnly":False,"minimumAvailability":None,"scanForAvailability":False}}
    response = ombi_api_request(ombi, "/api/v1/Settings/Radarr", body=json.dumps(fields))
    print(response.text)

def ombi_upload_lidarr_profiles(ombi: ombi_instance, lidarr_hostname: str, lidarr_port: int, lidarr_api_key: str, ssl: bool, base_url: str, root_dir: str):
    fields = {"enabled":True,"apiKey":lidarr_api_key,"defaultQualityProfile":1,"defaultRootPath": root_dir,"ssl":ssl,"subDir":base_url,"ip":lidarr_hostname,"port": str(lidarr_port),"albumFolder":True,"metadataProfileId":1,"addOnly":False}
    response = ombi_api_request(ombi, "/api/v1/Settings/Lidarr", body=json.dumps(fields))
    print(response.text)


def ombi_initial_setup_with_plex(hostname: str, port: int, path: str, plex_username: str, plex_password: str, scheme: str="https", validate_certificates: bool=False):
    login_fields = {"login": plex_username, "password": plex_password}
    uri = scheme + "://" + hostname + ":" + str(port) + path

    response = requests.get(uri + "/api/v2/Features/", data=json.dumps({"enabled": False, "name": "Movie4KRequests"}), verify=validate_certificates, headers={"content-type" : "application/json"})
    fields = {"applicationName": None,
        "applicationUrl": None,
        "customCss": None,
        "customDonationMessage": None,
        "customDonationUrl": None,
        "enableCustomDonations": False,
        "favicon": None,
        "hideAvailableFromDiscover": False,
        "id": 0,
        "logo": None,
        "recentlyAddedPage": False,
        "useCustomPage": False}

    #Something gets set on the backend when the landing page gets loaded - needed for next steps
    for url in ["/api/v1/Settings/customization", "/translations/en.json?v=92360805", "/api/v1/Settings/voteenabled", "/api/v1/Settings/issuesenabled", "/api/v1/Settings/LandingPage",
             "/ombi/api/v1/status/Wizard/", "/api/v1/Settings/Authentication", "/v1/Settings/clientid", "/api/v1/Settings/clientid"]:
        response = requests.get(uri + url, verify=validate_certificates, headers={"content-type" : "application/json"})


    response = requests.post(uri + "/api/v1/Plex/", data=json.dumps(login_fields), verify=validate_certificates, headers={"content-type" : "application/json"})
    response = requests.post(uri + "/api/v1/Identity/Wizard/", data=json.dumps({"login":"","password":"","usePlexAdminAccount":True}), verify=validate_certificates, headers={"content-type" : "application/json"})
    response = requests.post(uri + "/api/v2/wizard/config", data=json.dumps({"applicationName":"Ombi - nasinabox","applicationUrl":None,"logo":None}), verify=validate_certificates, headers={"content-type" : "application/json"})
    response = requests.post(uri + "/api/v1/Identity/Wizard/", data=json.dumps({"username":"admin","password":"admin","usePlexAdminAccount":False}), verify=validate_certificates, headers={"content-type" : "application/json"})

    response = requests.post(uri + "/api/v2/Features/enable", data=json.dumps({"name": "Movie4KRequests", "enabled": False}), verify=validate_certificates, headers={"content-type" : "application/json"})
    response = requests.post(uri + "/api/v1/Settings/Authentication", data=json.dumps({"allowNoPassword":True,"requiredDigit":None,"requiredLength":0,"requiredLowercase":None,"requireNonAlphanumeric":False,"requireUppercase":False,"enableOAuth":False,"enableHeaderAuth":False,"headerAuthVariable":None}), verify=validate_certificates, headers={"content-type" : "application/json"})








### *darr Methods

class darr_instance:
    def __init__(self, name, hostname: str, port: int, path: str, ssl: bool, v3: bool, api_key: str, scheme: str):
        self.name = name
        self.hostname = hostname
        self.port = port
        self.path = path
        self.scheme = scheme
        self.ssl = ssl
        self.v3 = v3
        self.api_key = api_key

def darr_add_root_folder(darr : darr_instance, name, path, api_version="v3", additional_fields={}):
    fields = {"path" : path, "name": name}
    fields.update(additional_fields)
    api_request_darr(darr.hostname, darr.port, darr.path + "/api/" + api_version + "/rootFolder", darr.api_key, fields, darr.scheme)

def darr_add_download_client(darr: darr_instance, name: str, torrent_hostname: str, torrent_port: int, torrent_path: str, torrent_username: str, torrent_password: str, implementation: str="Transmission", api_version="v3"):
    body = {"configContract" : implementation + "Settings", "enable": True, "implementation" : implementation, "implementationName" : implementation, "name" : name, "priority" : 1, "protocol" : "torrent", "tags" : []}
    fields = []
    fields.append({"name" : "host", "value" : name})
    fields.append({"name" : "port", "value" : torrent_port})
    fields.append({"name" : "urlBase", "value" : torrent_path})
    if torrent_username is not None:
        fields.append({"name" : "username", "value" : torrent_username})
    if torrent_password is not None:
        fields.append({"name" : "password", "value" : torrent_password})
    #Needed for Deluge
    fields.append({"name" : "tvCategory", "value" : ""})
    fields.append({"name" : "tvDirectory"})
    fields.append({"name" : "tvImportedCategory"})
    fields.append({"name" : "recentTvPriority", "value" : 0})
    fields.append({"name" : "olderTvPriority", "value" : 0})
    fields.append({"name" : "addPaused", "value" : False})
    fields.append({"name" : "useSsl", "value" : False})

    body.update({'fields' : fields})

    api_request_darr(darr.hostname, darr.port, darr.path + "/api/" + api_version + "/downloadclient", darr.api_key, body, darr.scheme, "POST")



def bazarr_configure_english_providers(darr: darr_instance, open_subtitles_username: str=None, open_subtitles_password: str=None, validate_certs=False):
    providers = ["betaseries", "opensubtitles", "opensubtitlescom", "subscenter", "supersubtitles", "tvsubtitles", "yifysubtitles"]
    body = []

    for provider in providers:
        body.append(("settings-general-enabled_providers", provider))

    if open_subtitles_username and open_subtitles_password:
        body.append(("settings-opensubtitles-username", open_subtitles_username))
        body.append(("settings-opensubtitles-password", open_subtitles_password))
        body.append(("settings-opensubtitlescom-username", open_subtitles_username))
        body.append(("settings-opensubtitlescom-password", open_subtitles_password))
        body.append(("settings-opensubtitles-ssl", "false"))
    
    response = requests.post(darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/system/settings?apikey=" + darr.api_key, data=body, verify=validate_certs)
    return response.status_code == 204

def bazarr_configure_sonarr_provider(darr: darr_instance, sonarr_instance: darr_instance, validate_certs=False):
    body = { \
        "settings-general-use_sonarr" : (None, True),
        "settings-sonarr-ip" : (None, "sonarr"),
        "settings-sonarr-base_url" : (None, sonarr_instance.path),
        "settings-sonarr-apikey" : (None, sonarr_instance.api_key)

    }
    headers = { \
        "x-api-key" : darr.api_key,
    }
    url = darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/system/settings"
    response = requests.post(url, files=body, headers=headers, verify=validate_certs)
    return response.status_code == 200

def bazarr_configure_radarr_provider(darr: darr_instance, radarr_instance: darr_instance, validate_certs=False):
    body = { \
        "settings-general-use_radarr" : (None, True),
        "settings-radarr-ip" : (None, "radarr"),
        "settings-radarr-base_url" : (None, radarr_instance.path),
        "settings-radarr-apikey" : (None, radarr_instance.api_key)

    }
    headers = { \
        "x-api-key" : darr.api_key,
    }
    url = darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/system/settings"
    response = requests.post(url, files=body, headers=headers, verify=validate_certs)
    return response.status_code == 200

def bazarr_configure_lang_profile(darr: darr_instance, language="en", validate_certs=False) -> bool:
    language_profiles = json.dumps([{ \
        "profileId": 1,
        "name": language,
        "items": [ \
            {
                "id": 1,
                "language": language,
                "audio_exclude": False,
                "hi": False,
                "forced": False
            }
        ],
        "cutoff": 65535,
        "mustContain": [],
        "mustNotContain": []
    }])

    body = { \
        "settings-general-serie_default_enabled" : (None,True),
        "settings-general-movie_default_enabled" : (None,True),
        "settings-general-serie_default_profile" : (None,1),
        "settings-general-movie_default_profile" :(None,1),
        "languages-enabled" : (None,language),
        "languages-profiles" : (None, language_profiles)
    }

    headers = {"x-api-key": darr.api_key}

    url = darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/system/settings"
    response = requests.post(url, files=body, headers=headers, verify=validate_certs)
    return response.status_code == 204


def make_post_request_indexers(url, json_body, headers, darr_name, verify):
    resp = requests.post(url, json=json_body, headers=headers, verify=verify)
    if (resp.status_code == 400 and 
        ("but no results in the configured categories" in resp.text or
         "unable to connect to indexer" in resp.text or
          "Query successful, but no results in the configured categories were returned from your indexer" in resp.text)):
        #We should blacklist this indexer
        file = open("blacklist.txt", "a+")
        file.writelines([darr_name + ":" + json_body["name"] + "\n"])
        file.close()
    print(resp)

def prowlarr_get_all_public_indexers(prowlarr: darr_instance, validate_certs: bool, api_key: str, indexer_languages: list=["en-AU", "en-GB", "en-US"], protocol="torrent") -> list:
    url = prowlarr.scheme + "://" + prowlarr.hostname + ":" + str(prowlarr.port) + prowlarr.path + "/api/v1/indexer/schema"
    response_json = requests.get(url, verify=validate_certs, headers={"x-api-key": api_key}).json()

    public_indexers_json = [x for x in response_json if x["privacy"].lower() == "public"]
    if indexer_languages:
        public_indexers_json = [x for x in public_indexers_json if x["language"] in indexer_languages]
    if protocol:
        public_indexers_json = [x for x in public_indexers_json if x["protocol"] == protocol]


    return public_indexers_json


def prowlarr_add_indexers(prowlarr: darr_instance, validate_certs: bool, api_key: str, indexers: list) -> bool:
    some_success = False
    if not os.path.exists("blacklist.txt"):
        file = open("blacklist.txt", "w")
        file.close()
    blacklisted_sites = list(set([x.strip().split(":")[-1] for x in open("blacklist.txt", "r").readlines() if x.strip().split(":")[0] == "prowlarr"]))

    def add_to_blacklist(name: str) -> None:
        file = open("blacklist.txt", "a+")
        file.writelines(["prowlarr:" + json_body["name"] + "\n"])
        file.close()

    for indexer in indexers:
        if indexer["name"] in blacklisted_sites:
            continue
        url = prowlarr.scheme + "://" + prowlarr.hostname + ":" + str(prowlarr.port) + prowlarr.path + "/api/v1/indexer?"
        json_body = indexer
        response = requests.post(url, headers={"x-api-key": api_key}, json=json_body, verify=validate_certs)
        response_json = response.json()
        if response.status_code == 400:
            if response_json[0]["errorMessage"] == "Should be unique":
                continue
            if response_json[0]["errorMessage"].endswith("blocked by CloudFlare Protection."):
                add_to_blacklist(indexer["name"])
            print("Unable to add indexer " + indexer["name"] + "\nReason: " + response.text)
            add_to_blacklist(indexer["name"])
        elif response.status_code == 201:
            some_success = True
        else:
            add_to_blacklist(indexer["name"])


    return some_success


def prowlarr_add_radarr(prowlarr_instance: darr_instance, radarr_instance: darr_instance, internal_prowlarr_instance: darr_instance, validate_ssl: bool=False) -> bool:
    url = prowlarr_instance.scheme + "://" + prowlarr_instance.hostname + ":" + str(prowlarr_instance.port) + prowlarr_instance.path + "/api/v1/applications?"
    body = {
        "configContract": "RadarrSettings",
        "implementation": "Radarr",
        "implementationName": "Radarr",
        "infoLink": "https://wiki.servarr.com/prowlarr/supported#radarr",
        "name": "Radarr",
        "syncLevel": "addOnly",
        "tags": [],
        "fields": [
            {
                "name": "prowlarrUrl",
                "value": internal_prowlarr_instance.scheme + "://" + internal_prowlarr_instance.hostname + ":" + str(internal_prowlarr_instance.port)
            },
            {
                "name": "baseUrl",
                "value": radarr_instance.scheme + "://" + radarr_instance.hostname + ":" + str(radarr_instance.port)
            },
            {
                "name": "apiKey",
                "value": radarr_instance.api_key
            },
            {
                "name": "syncCategories",
                "value": [2000, 2010, 2020, 2030, 2040, 2045, 2050, 2060, 2070, 2080]
            }
        ]
    }

    response = requests.post(url, headers={"x-api-key": prowlarr_instance.api_key}, verify=validate_ssl, json=body)
    if response.status_code == 201:
        print("Added Radarr to Prowlarr")
        return True
    elif response.status_code == 400:
        json_response = response.json()
        if json_response[0]["errorMessage"] == "Should be unique":
            return True
        else:
            print("Couldnt add Radarr instance to Prowlarr")
    
    return False

def prowlarr_add_sonarr(prowlarr_instance: darr_instance, sonarr_instance: darr_instance, internal_prowlarr_instance: darr_instance, validate_ssl: bool=False) -> bool:
    url = prowlarr_instance.scheme + "://" + prowlarr_instance.hostname + ":" + str(prowlarr_instance.port) + prowlarr_instance.path + "/api/v1/applications?"
    body = {
        "configContract": "SonarrSettings",
        "implementation": "Sonarr",
        "implementationName": "Sonarr",
        "infoLink": "https://wiki.servarr.com/prowlarr/supported#radarr",
        "name": "Sonarr",
        "syncLevel": "addOnly",
        "tags": [],
        "fields": [
            {
                "name": "prowlarrUrl",
                "value": internal_prowlarr_instance.scheme + "://" + internal_prowlarr_instance.hostname + ":" + str(internal_prowlarr_instance.port)
            },
            {
                "name": "baseUrl",
                "value": sonarr_instance.scheme + "://" + sonarr_instance.hostname + ":" + str(sonarr_instance.port)
            },
            {
                "name": "apiKey",
                "value": sonarr_instance.api_key
            },
            {
                "name": "syncCategories",
                "value": [5000, 5010, 5020, 5030, 5040, 5045, 505]
            },
            {
                "name": "animeSyncCategories",
                "value": [5070]
            }
        ]
    }

    response = requests.post(url, headers={"x-api-key": prowlarr_instance.api_key}, verify=validate_ssl, json=body)
    if response.status_code == 201:
        print("Added Radarr to Prowlarr")
        return True
    elif response.status_code == 400:
        json_response = response.json()
        if json_response[0]["errorMessage"] == "Should be unique":
            return True
        else:
            print("Couldnt add Radarr instance to Prowlarr")
    
    return False

def prowlarr_set_authentication(prowlarr_instance: darr_instance, username: str, password: str, authentication_method: str="forms", validate_ssl: bool=False) -> bool:
    url = prowlarr_instance.scheme + "://" + prowlarr_instance.hostname + ":" + str(prowlarr_instance.port) + prowlarr_instance.path + "/api/v1/config/host"

    body = {
    "bindAddress": "*",
    "port": 9696,
    "sslPort": 6969,
    "enableSsl": False,
    "launchBrowser": True,
    "authenticationMethod": "forms",
    "authenticationRequired": "disabledForLocalAddresses",
    "analyticsEnabled": True,
    "username": "nasinabox",
    "password": "nasinabox",
    "logLevel": "info",
    "consoleLogLevel": "",
    "branch": "develop",
    "apiKey": prowlarr_instance.api_key,
    "sslCertPath": "",
    "sslCertPassword": "",
    "urlBase": "/prowlarr",
    "instanceName": "Prowlarr",
    "updateAutomatically": False,
    "updateMechanism": "docker",
    "updateScriptPath": "",
    "proxyEnabled": False,
    "proxyType": "http",
    "proxyHostname": "",
    "proxyPort": 8080,
    "proxyUsername": "",
    "proxyPassword": "",
    "proxyBypassFilter": "",
    "proxyBypassLocalAddresses": True,
    "certificateValidation": "enabled",
    "backupFolder": "Backups",
    "backupInterval": 7,
    "backupRetention": 28,
    "historyCleanupDays": 365,
    "id": 1
    }

    response = requests.put(url, verify=validate_ssl, json=body, headers={"x-api-key": prowlarr_instance.api_key})
    if response.status_code == 202:
        return True
    else:
        raise Exception("Unknown issue setting authentication method for Prowlarr\n" + response.json()[0]["errorMessage"])




def darr_add_all_configured_jacket_indexers(darr: darr_instance, jackett_api_key: str, jackett_scheme: str, jackett_hostname: str, jackett_port: int, jackett_path, int_jackett_scheme, int_jackett_hostname, int_jackett_port, int_jackett_path, validate_certs=False, categories=[5030, 5040], api_version="v3"):
    url = jackett_scheme + "://" + jackett_hostname + ":" + str(jackett_port) + jackett_path + "/api/v2.0/indexers/?configured=true"
    response_json = requests.get(url, verify=validate_certs).json()
    
    current_darr_indexers = requests.get(f"{darr.scheme}://{darr.hostname}:" + str(darr.port) + darr.path + "/api/" + api_version + "/indexer", headers={"x-api-key" : darr.api_key}, verify=validate_certs).json()
    darr_indexers = [x["name"] for x in current_darr_indexers]

    blacklisted_sites = None
    if os.path.exists("blacklist.txt"):
        #Grab all lines from blacklist.txt which start with darr.name, separated by ':'
        blacklisted_sites = list(set([x.strip().split(":")[-1] for x in open("blacklist.txt", "r").readlines() if x.strip().split(":")[0] == darr.name]))


    threads = []

    for indexer in response_json:
        indexer_dict = {}
        indexer_dict["id"] = indexer["id"]

        if indexer_dict["id"] in darr_indexers:
            continue
        cap_matches = [x["ID"] for x in indexer["caps"] if int(x["ID"]) in categories]
        if len(cap_matches) < 1:
            continue
        
        if blacklisted_sites is not None and indexer["id"] in blacklisted_sites:
            continue

        indexer_dict["torznab"] = int_jackett_scheme + "://" + int_jackett_hostname + ":" + str(int_jackett_port) + int_jackett_path + "/api/v2.0/indexers/" + indexer_dict["id"] + "/results/torznab/"

        fields = [ \
            {"name": "baseUrl", "value": indexer_dict["torznab"]},
            {"name": "apiPath", "value": "/api"},
            {"name": "apiKey", "value": jackett_api_key},
            {"name": "categories", "value": categories},
            {"name": "animeCategories", "value": [5070]},
            {"name": "additionalParameters"},
            {"name": "minimumSeeders", "value": 1},
            {"name": "seedCriteria.seedRatio"},
            {"name": "seedCriteria.seedTime"},
            {"name": "seedCriteria.seasonPackSeedTime"}
        ]

        body = { \
            "configContract" : "TorznabSettings",
            "enableAutomaticSearch": True,
            "enableInteractiveSearch": True,
            "enableRss": True,
            "fields": fields,
            "implementation": "Torznab",
            "implementationName": "Torznab",
            "infoLink": "https://wiki.servarr.com/sonarr/supported#torznab",
            "name": indexer_dict["id"],
            "priority": 25,
            "protocol": "torrent",
            "supportsRss": True,
            "supportsSearch": True,
            "tags": []
        }

        url = darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/" + api_version + "/indexer?"

        th = threading.Thread(target=make_post_request_indexers, args=(url, body, {"x-api-key" : darr.api_key}, darr.name, validate_certs,))
        threads.append(th)
        th.start()

    for thread in threads:
        thread.join()





        


#torznab_url = jackett_scheme + "://" + jackett_hostname + ":" + str(jackett_port) + "/jackett/api/v2.0/indexers/{id}/results/torznab".format(id)

def configure_all_apps(vars):



    sonarr = darr_instance("sonarr", vars['hostname'], vars['port'], "/sonarr", True, True, vars['apikey'], "https")
    lidarr = darr_instance("lidarr", vars['hostname'], vars['port'], "/lidarr", True, True, vars['apikey'], "https")
    radarr = darr_instance("radarr", vars['hostname'], vars['port'], "/radarr", True, True, vars['apikey'], "https")
    bazarr = darr_instance("bazarr", vars['hostname'], vars['port'], "/bazarr", True, True, vars['apikey'], "https")
    readarr = darr_instance("readarr", vars['hostname'], vars['port'], "/readarr", True, True, vars['apikey'], "https")
    prowlarr_instance = darr_instance("prowlarr", vars['hostname'], vars['port'], "/prowlarr", True, True, vars['apikey'], "https")
    prowlarr_internal_instance = darr_instance("prowlarr_internal", "prowlarr", 9696, "/prowlarr", False, False, vars['apikey'], "http")


    
    darr_add_download_client(sonarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge")
    darr_add_download_client(lidarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge", api_version="v1")
    darr_add_download_client(radarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge")
    darr_add_download_client(readarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge", api_version="v1")

    darr_add_root_folder(sonarr, "/tv/", "/tv/")
    darr_add_root_folder(lidarr, "/music/", "/music/", api_version="v1", additional_fields={"defaultMetadataProfileId": "1", "defaultQualityProfileId": "1", "defaultTags": []})
    darr_add_root_folder(radarr, "/movies", "/movies")
    darr_add_root_folder(readarr, "/books/", "/books/", additional_fields={"defaultMetadataProfileId": "1", "defaultQualityProfileId": "1", "defaultTags": [], "host": "localhost", "isCalibreLibrary": False, "outputProfile": "default", "port": 8080, "useSsl": False}, api_version="v1")

    bazarr_configure_english_providers(bazarr, vars['open_subtitles_username'], vars['open_subtitles_password'])
    bazarr_configure_sonarr_provider(bazarr, sonarr)
    bazarr_configure_radarr_provider(bazarr, radarr)
    bazarr_configure_lang_profile(bazarr)

    ombi = ombi_instance(vars["hostname"], 443, "/ombi", vars["apikey"], "https")
    if "plex_username" in vars and "plex_password" in vars:
        ombi_initial_setup_with_plex(vars["hostname"], 443, "/ombi", vars["plex_username"], vars["plex_password"], "https")
    ombi_upload_sonarr_profiles(ombi, "sonarr", 8989, True, vars["apikey"], False, "/sonarr", 4, 1, 1, 1)
    ombi_upload_radarr_profiles(ombi, "radarr", "7878", vars["apikey"], False, "/radarr", 4, "/movies")
    ombi_upload_lidarr_profiles(ombi, "lidarr", "8686", vars["apikey"], False, "/lidarr", "/music/")

    darr_add_all_configured_jacket_indexers(sonarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "",categories=[5030, 5040, 5000, 5010, 5020, 5045, 5050, 5060, 5070, 5080])
    darr_add_all_configured_jacket_indexers(radarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "", categories=[2000,2010,2020, 2030, 2040,2050,2060, 2070, 2080])
    darr_add_all_configured_jacket_indexers(readarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "", categories=[3030, 7020, 8010], api_version="v1")
    darr_add_all_configured_jacket_indexers(lidarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "",categories=[3000,3010,3020,3030,3040], api_version="v1")

    indexers = prowlarr_get_all_public_indexers(prowlarr_instance, False, prowlarr_instance.api_key)
    prowlarr_add_indexers(prowlarr_instance, False, prowlarr_instance.api_key, indexers)
    prowlarr_add_radarr(prowlarr_instance, radarr, prowlarr_internal_instance)
    prowlarr_add_sonarr(prowlarr_instance, sonarr, prowlarr_internal_instance)
    prowlarr_set_authentication(prowlarr_instance, "nasinabox", "nasinabox")
   

    




def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--hostname", required=True, help="IP Address/Hostname of the *arr clients")
    parser.add_argument("-p", "--port", required=True, help="Port of the *arr clients")
    parser.add_argument("-a", "--apikey", required=True, help="IP Address of the *arr clients")
    parser.add_argument("--open-subtitles-username", help="OpenSubtitles.org/.com username")
    parser.add_argument("--open-subtitles-password", help="OpenSubtitles.org/.com password")
    parser.add_argument("--plex-username", help="Plex username")
    parser.add_argument("--plex-password", help="Plex password")
    args = vars(parser.parse_args())

    configure_all_apps(args)
    print("success")

main()
