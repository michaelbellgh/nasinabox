import threading
import requests, json, argparse, os, json, glob
import urllib3

from urllib.parse import quote

urllib3.disable_warnings()

customisation_params = {
    "ombi_title": "Ombi",
    "url_mode": "path",
    "instance_name": "dennas",
    "sonarr_path": "/sonarr",
    "lidarr_path": "/lidarr",
    "radarr_path": "/radarr",
    "torrent_path": "/deluge",
    "ombi_path": "/ombi",
    "validate_ssl": False,
    "preferr_dv": False

}

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
    url = ombi.scheme + "://" + ombi.hostname + ":" + str(ombi.port) + ombi.path
    url = url.strip("/")

    url += "/" + api_path.lstrip('/')


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

    uri = scheme + "://" + hostname + ":" + str(port) + path + "api/v2/wizard/config"
    response = requests.post(uri, data=json.dumps(fields), verify=validate_certificates, headers={"content-type" : "application/json"})

    login_results = response.json()
    return login_results["applicationName"]


def ombi_get_quality_profiles_from_sonarr(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfiles" : 0, "port" : str(sonarr_port), "qualityProfile" : None, "qualityProfileAnime" : None, "rootPath" : None, "rootPathAnime" : None, "seasonFolders" : False, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "api/v1/Sonarr/Profiles/", body=json.dumps(fields))
    final_names = []
    for profile in response.json():
        final_names.append((profile['id'], profile['name']))
    return final_names

def ombi_get_root_dirs_from_sonarr(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfiles" : 0, "port" : str(sonarr_port), "qualityProfile" : None, "qualityProfileAnime" : None, "rootPath" : None, "rootPathAnime" : None, "seasonFolders" : False, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "api/v1/Sonarr/RootFolders", body=json.dumps(fields))
    final_names = []
    for profile in response.json():
        final_names.append((profile['id'], profile['path']))
    return final_names

def ombi_get_lang_profiles_from_sonarr(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfiles" : 0, "port" : str(sonarr_port), "qualityProfile" : None, "qualityProfileAnime" : None, "rootPath" : None, "rootPathAnime" : None, "seasonFolders" : False, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "api/v1/Sonarr/v3/languageprofiles", body=json.dumps(fields))
    final_names = []
    for profile in response.json():
        final_names.append((profile['id'], profile['name']))
    return final_names

def ombi_upload_sonarr_profiles(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str, quality_profile: int, root_dir: int, language_profile: int, language_profile_anime: int):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfile" : language_profile, "languageProfileAnime" : language_profile_anime,"port" : str(sonarr_port), "qualityProfile" : quality_profile, "qualityProfileAnime" : quality_profile, "rootPath" : root_dir, "rootPathAnime" : root_dir, "seasonFolders" : True, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "api/v1/Settings/Sonarr", body=json.dumps(fields))
    print(response.text)

def ombi_upload_radarr_profiles(ombi: ombi_instance, radarr_hostname: str, radarr_port: int, radarr_api_key: str, ssl: bool, base_url: str, quality_profile: int, root_dir: str):
    fields = {"radarr":{"enabled":True,"apiKey":radarr_api_key,"defaultQualityProfile":quality_profile,"defaultRootPath":root_dir,"ssl":ssl,"subDir":base_url,"ip":radarr_hostname,"port":radarr_port,"addOnly":False,"minimumAvailability":"Released","scanForAvailability":False},
               "radarr4K":{"enabled":False,"apiKey":radarr_api_key,"defaultQualityProfile":0,"defaultRootPath":root_dir,"ssl":ssl,"subDir":None,"ip":radarr_hostname,"port":radarr_port,"addOnly":False,"minimumAvailability":None,"scanForAvailability":False}}
    response = ombi_api_request(ombi, "api/v1/Settings/Radarr", body=json.dumps(fields))
    print(response.text)

def ombi_upload_lidarr_profiles(ombi: ombi_instance, lidarr_hostname: str, lidarr_port: int, lidarr_api_key: str, ssl: bool, base_url: str, root_dir: str):
    fields = {"enabled":True,"apiKey":lidarr_api_key,"defaultQualityProfile":1,"defaultRootPath": root_dir,"ssl":ssl,"subDir":base_url,"ip":lidarr_hostname,"port": str(lidarr_port),"albumFolder":True,"metadataProfileId":1,"addOnly":False}
    response = ombi_api_request(ombi, "api/v1/Settings/Lidarr", body=json.dumps(fields))
    print(response.text)


def ombi_initial_setup(hostname: str, port: int, path: str, plex_username: str, plex_password: str, api_key: str, scheme: str="https", validate_certificates: bool=False, local_username: str="admin", local_password: str="password", app_url: str="") -> bool:
    
    uri = scheme + "://" + hostname + ":" + str(port) + path
    if not uri.endswith("/"):
        uri += "/"
    
    def ombi_std_post(endpoint, data):
        return requests.post(uri + endpoint, data=json.dumps(data), verify=validate_certificates, headers={"content-type" : "application/json", "ApiKey": api_key})
    
    def ombi_std_put(endpoint, data):
        return requests.put(uri + endpoint, data=json.dumps(data), verify=validate_certificates, headers={"content-type" : "application/json", "ApiKey": api_key})

    if plex_username is not None and plex_password is not None:
        response = ombi_std_post("api/v1/Plex/", {"login": plex_username, "password": plex_password})
        response = ombi_std_post("api/v1/Identity/Wizard/", {"username":"","password":"","usePlexAdminAccount":True})

    response = ombi_std_post("api/v2/wizard/config", {"applicationName": "Ombi", "applicationUrl": app_url, "logo": None})
    response = ombi_std_post("api/v1/Identity/Wizard/", {"password": local_password, "username": local_username, "usePlexAdminAccount": False})

    ombi_std_post("api/v1/Identity/Wizard/", {"username": local_username, "password": local_password, "usePlexAdminAccount": False})
    ombi_std_post("api/v1/Settings/Authentication", {
        "allowNoPassword": True,
        "requiredDigit": None,
        "requiredLength": 0,
        "requiredLowercase": None,
        "requireNonAlphanumeric": False,
        "requireUppercase": False,
        "enableOAuth": False,
        "enableHeaderAuth": False,
        "headerAuthVariable": None,
        "headerAuthCreateUser": False
        })
    ombi_std_post("api/v2/Features/enable", [{"name":"Movie4KRequests","enabled": True},{"name":"OldTrendingSource","enabled": False}])
    



### *darr Methods

class darr_instance:
    def __init__(self, name, hostname: str, port: int, path: str, ssl: bool, v3: bool, api_key: str, scheme: str, internal_port: int, ssl_port: int, internal_hostname: str, internal_scheme: str):
        self.name = name
        self.hostname = hostname
        self.port = port
        self.path = path
        self.scheme = scheme
        self.ssl = ssl
        self.v3 = v3
        self.api_key = api_key
        self.ssl_port = ssl_port
        self.internal_port = internal_port
        self.internal_hostname = internal_hostname
        self.internal_scheme = internal_scheme

def darr_add_root_folder(darr : darr_instance, name, path, api_version="v3", additional_fields={}):
    fields = {"path" : path, "name": name}
    fields.update(additional_fields)
    api_request_darr(darr.hostname, darr.port, darr.path + "/api/" + api_version + "/rootFolder", darr.api_key, fields, darr.scheme)

def darr_add_download_client(darr: darr_instance, name: str, torrent_hostname: str, torrent_port: int, torrent_path: str, torrent_username: str, torrent_password: str, implementation: str="Transmission", api_version="v3"):
    body = {"configContract" : implementation + "Settings", "enable": True, "implementation" : implementation, "implementationName" : implementation, "name" : name, "priority" : 1, "protocol" : "torrent", "tags" : []}
    fields = []
    fields.append({"name" : "host", "value" : torrent_hostname})
    fields.append({"name" : "port", "value" : torrent_port})
    fields.append({"name" : "urlBase"})
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


def darr_get_tag_dict(darr: darr_instance, validate_cert: bool):
    tags = requests.get(darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/v3/tag?apikey=" + darr.api_key, verify=validate_cert).json()
    d = {}
    for item in tags:
        d[item["label"]] = item["id"]

    return d


def bazarr_configure_english_providers(darr: darr_instance, open_subtitles_username: str=None, open_subtitles_password: str=None, validate_certs=False):
    providers = ["betaseries", "opensubtitlescom", "subscenter", "supersubtitles", "tvsubtitles", "yifysubtitles"]
    body = []

    for provider in providers:
        body.append(("settings-general-enabled_providers", provider))

    if open_subtitles_username and open_subtitles_password:
        body.append(("settings-opensubtitlescom-username", open_subtitles_username))
        body.append(("settings-opensubtitlescom-password", open_subtitles_password))
        body.append(("settings-opensubtitles-ssl", "false"))
    
    url = darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/system/settings?apikey=" + darr.api_key
    response = requests.post(darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/system/settings?apikey=" + darr.api_key, data=body, verify=validate_certs)
    return response.status_code == 204

def darr_add_release_profile(darr: darr_instance, name: str, required: list, ignore: list, preferred: list, tag_ids: list, validate_cert: bool):

    profiles = requests.get(darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/v3/releaseprofile?apikey=" + darr.api_key, verify=validate_cert).json()
    names = [x["name"] for x in profiles]

    tags = darr_get_tag_dict(darr, validate_cert)



    if name in names:
        print(f"{name} already in release profiles. Skipping")
        return None


    body = {}
    body["name"] = name
    body["enabled"] = True
    body["includePreferredWhenRenaming"] = False
    body["indexerId"] = 0
    
    body["required"] = []
    if required is not None and isinstance(required, list) and len(required) > 0:
        for term in required:
            if isinstance(term, str):
                body["required"].append(term)

    body["ignored"] = []
    if ignore is not None and isinstance(ignore, list) and len(ignore) > 0:
        
        for term in ignore:
            if isinstance(term, str):
                body["ignored"].append(term)

    body["preferred"] = []
    if preferred is not None and isinstance(preferred, list) and len(preferred) > 0: 
        for term in preferred:
            if isinstance(term, dict) and all(k in term for k in ("key", "value")):
                body["preferred"].append(term)

    body["tags"] = []
    if tag_ids is not None and isinstance(tag_ids, list) and len(tag_ids) > 0:
        for term in tag_ids:
            if isinstance(term, str) and term in tags:
                body["tags"].append(tags[term])
    


    response = requests.post(darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/v3/releaseprofile?apikey=" + darr.api_key, json=body, verify=validate_cert)
    return response.status_code == 200



def darr_add_tag(darr: darr_instance, name: str, validate_cert=False):
    tags = darr_get_tag_dict(darr, validate_cert=False)
    if not name in tags:
        response = requests.post(darr.scheme + "://" + darr.hostname + ":" + str(darr.port) + darr.path + "/api/v3/tag?apikey=" + darr.api_key, verify=validate_cert, json={"label": name})
        return response.status_code == 201
    return False

def bazarr_configure_sonarr_provider(darr: darr_instance, sonarr_instance: darr_instance, validate_certs=False):
    body = { \
        "settings-general-use_sonarr" : (None, "true"),
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
        "settings-general-use_radarr" : (None, "true"),
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
    static_lang_profile = '[{"profileId":1,"name":"' + language +'","items":[{"id":1,"language":"' + language + '","audio_exclude":"False","hi":"False","forced":"False"}],"cutoff":null,"mustContain":[],"mustNotContain":[],"originalFormat":false}]'

    body = { \
        "settings-general-serie_default_enabled" : (None, "true"),
        "settings-general-movie_default_enabled" : (None,"true"),
        "settings-general-serie_default_profile" : (None,"1"),
        "settings-general-movie_default_profile" :(None, "1"),
        "languages-enabled" : (None,language),
        "languages-profiles" : (None, static_lang_profile)
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


def prowlarr_add_indexers(prowlarr: darr_instance, validate_certs: bool, api_key: str, indexers: list, flaresolverr_tag: int=1) -> bool:
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
        if flaresolverr_tag != 0:
            json_body["tags"] = [flaresolverr_tag]
        json_body["appProfileId"] = 1
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
        "syncLevel": "fullSync",
        "tags": [],
        "fields": [
            {
                "name": "prowlarrUrl",
                "value": internal_prowlarr_instance.scheme + "://" + internal_prowlarr_instance.hostname + ":" + str(internal_prowlarr_instance.port)
            },
            {
                "name": "baseUrl",
                "value": radarr_instance.internal_scheme + "://" + radarr_instance.internal_hostname + ":7878" + radarr_instance.path
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
        print("Added Sonarr to Prowlarr")
        return True
    elif response.status_code == 400:
        json_response = response.json()
        if json_response[0]["errorMessage"] == "Should be unique":
            return True
        else:
            print("Couldnt add Sonarr instance to Prowlarr")
    
    return False

def prowlarr_add_sonarr(prowlarr_instance: darr_instance, sonarr_instance: darr_instance, internal_prowlarr_instance: darr_instance, validate_ssl: bool=False) -> bool:
    url = prowlarr_instance.scheme + "://" + prowlarr_instance.hostname + ":" + str(prowlarr_instance.port) + prowlarr_instance.path + "/api/v1/applications?"
    body = {
        "configContract": "SonarrSettings",
        "implementation": "Sonarr",
        "implementationName": "Sonarr",
        "infoLink": "https://wiki.servarr.com/prowlarr/supported#radarr",
        "name": "Sonarr",
        "syncLevel": "fullSync",
        "tags": [],
        "fields": [
            {
                "name": "prowlarrUrl",
                "value": internal_prowlarr_instance.scheme + "://" + internal_prowlarr_instance.hostname + ":" + str(internal_prowlarr_instance.port)
            },
            {
                "name": "baseUrl",
                "value": sonarr_instance.internal_scheme + "://" + sonarr_instance.internal_hostname + ":8989" + sonarr_instance.path
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

def prowlarr_add_readarr(prowlarr_instance: darr_instance, readarr_instance: darr_instance, internal_prowlarr_instance: darr_instance, validate_ssl: bool=False) -> bool:
    url = prowlarr_instance.scheme + "://" + prowlarr_instance.hostname + ":" + str(prowlarr_instance.port) + prowlarr_instance.path + "/api/v1/applications?"
    body = {
        "configContract": "ReadarrSettings",
        "implementation": "Readarr",
        "implementationName": "Readarr",
        "infoLink": "https://wiki.servarr.com/prowlarr/supported#radarr",
        "name": "Readarr",
        "syncLevel": "fullSync",
        "tags": [],
        "fields": [
            {
                "name": "prowlarrUrl",
                "value": internal_prowlarr_instance.scheme + "://" + internal_prowlarr_instance.hostname + ":" + str(internal_prowlarr_instance.port)
            },
            {
                "name": "baseUrl",
                "value": readarr_instance.internal_scheme + "://" + readarr_instance.internal_hostname + ":8787" + readarr_instance.path
            },
            {
                "name": "apiKey",
                "value": readarr_instance.api_key
            },
            {
                "name": "syncCategories",
                "value": [3030, 7000, 7010, 7020, 7030, 7040, 7050, 7060]
            }
        ]
    }

    response = requests.post(url, headers={"x-api-key": prowlarr_instance.api_key}, verify=validate_ssl, json=body)
    if response.status_code in (200, 201, 202):
        print("Added Radarr to Prowlarr")
        return True
    elif response.status_code == 400:
        json_response = response.json()
        if json_response[0]["errorMessage"] == "Should be unique":
            return True
        else:
            print("Couldnt add Readarr instance to Prowlarr")
    
    return False

def prowlarr_add_lidarr(prowlarr_instance: darr_instance, lidarr_instance: darr_instance, internal_prowlarr_instance: darr_instance, validate_ssl: bool=False) -> bool:
    url = prowlarr_instance.scheme + "://" + prowlarr_instance.hostname + ":" + str(prowlarr_instance.port) + prowlarr_instance.path + "/api/v1/applications?"
    body = {
        "configContract": "LidarrSettings",
        "implementation": "Lidarr",
        "implementationName": "Lidarr",
        "infoLink": "https://wiki.servarr.com/prowlarr/supported#radarr",
        "name": "Lidarr",
        "syncLevel": "fullSync",
        "tags": [],
        "fields": [
            {
                "name": "prowlarrUrl",
                "value": internal_prowlarr_instance.scheme + "://" + internal_prowlarr_instance.hostname + ":" + str(internal_prowlarr_instance.port)
            },
            {
                "name": "baseUrl",
                "value": lidarr_instance.internal_scheme + "://" + lidarr_instance.internal_hostname + ":8686" + lidarr_instance.path
            },
            {
                "name": "apiKey",
                "value": lidarr_instance.api_key
            },
            {
                "name": "syncCategories",
                "value": [3000, 3010, 3030, 3040, 3050, 3060]
            }
        ]
    }

    response = requests.post(url, headers={"x-api-key": prowlarr_instance.api_key}, verify=validate_ssl, json=body)
    if response.status_code in (200, 201, 202):
        print("Added Lidarr to Prowlarr")
        return True
    elif response.status_code == 400:
        json_response = response.json()
        if json_response[0]["errorMessage"] == "Should be unique":
            return True
        else:
            print("Couldnt add Lidarr instance to Prowlarr")
    
    return False

def darr_set_authentication(darr_instance: darr_instance, instance_name: str, username: str, password: str, authentication_method: str="forms", api_version="v1", validate_ssl: bool=False) -> bool:
    url = darr_instance.scheme + "://" + darr_instance.hostname + ":" + str(darr_instance.port) + darr_instance.path + "/api/" + api_version + "/config/host"


    body = {
    "bindAddress": "*",
    "port": darr_instance.internal_port,
    "sslPort": darr_instance.ssl_port,
    "enableSsl": False,
    "launchBrowser": True,
    "authenticationMethod": "forms",
    "authenticationRequired": "disabledForLocalAddresses",
    "analyticsEnabled": True,
    "username": username,
    "password": password,
    "passwordConfirmation": password,
    "logLevel": "info",
    "logSizeLimit": 1,
    "consoleLogLevel": "",
    "branch": "develop",
    "apiKey": darr_instance.api_key,
    "sslCertPath": "",
    "sslCertPassword": "",
    "urlBase": darr_instance.path if customisation_params["url_mode"] == "path" else "",
    "instanceName": instance_name,
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

    response = requests.put(url, verify=validate_ssl, json=body, headers={"x-api-key": darr_instance.api_key})	
    if response.status_code == 202 or response.status_code == 200:	
        return True	
    else:	
        raise Exception("Unknown issue setting authentication method for " + darr_instance.name + "\n" + response.json()[0]["errorMessage"])



def prowlarr_add_flaresolverr(prowlarr_instance: darr_instance, validate_ssl: bool=False, flaresolverr_hostname: str="flaresolverr", flaresolverr_port: int=8191) -> bool:
    url = prowlarr_instance.scheme + "://" + prowlarr_instance.hostname + ":" + str(prowlarr_instance.port) + prowlarr_instance.path + "/api/v1/indexerProxy/?"

    indexers = requests.get(url, verify=validate_ssl, headers={"x-api-key": prowlarr_instance.api_key})
    names = [x["name"] for x in indexers.json()]


    use_put = 'FlareSolverr' in names

    json_data = {
        "configContract": "FlareSolverrSettings",
        "fields": [
            {"name": "host", "value": "http://" + flaresolverr_hostname + ":" + str(flaresolverr_port)},
            {"name": "requestTimeout", "value": 60}
        ],
        "implementation": "FlareSolverr",
        "implementationName": "FlareSolverr",
        "includeHealthWarnings": False,
        "infoLink": "https://wiki.servarr.com/prowlarr/supported#flaresolverr",
        "name": "FlareSolverr",
        "onHealthIssue": False,
        "supportsOnHealthIssue": False,
        "tags": [
            1
        ]
        
    }
    if use_put:
        json_data["id"] = [x["id"] for x in indexers.json() if x["name"] == "FlareSolverr"][0]

    response = None

    if use_put:
        response = requests.put(url, verify=validate_ssl, json=json_data, headers={"x-api-key": prowlarr_instance.api_key})
    else:
        response = requests.post(url, verify=validate_ssl, json=json_data, headers={"x-api-key": prowlarr_instance.api_key})
    if response.status_code in (200,201,202):
        return True
    else:
        raise Exception("Unknown issue adding FlareSolverr\n" + response.text)



        
def add_sonarr_show(sonarr_instance: darr_instance, tvdb_id: int, monitor: str="all", search_for_missing_episodes: bool=True, quality_profile_id: int=1, language_profile_id: int=1, root_folder: str="/tv") -> bool:
    url = sonarr_instance.scheme + "://" + sonarr_instance.hostname + ":" + str(sonarr_instance.port) + sonarr_instance.path + "/api/v3/series/lookup?term=" + quote("tvdb:" + str(tvdb_id))

    response = requests.get(url, verify=sonarr_instance.ssl, headers={"x-api-key": sonarr_instance.api_key})
    if response.status_code == 200:
        payload = response.json()
        if len(payload) != 1:
            return False
        
        payload = payload[0]

        add_url = sonarr_instance.scheme + "://" + sonarr_instance.hostname + ":" + str(sonarr_instance.port) + sonarr_instance.path + "/api/v3/series"

        additional_fields = {
            "addOptions": {
                "ignoreEpisodeWithFiles": False,
                "ignoreEpisodeWithtoutFiles": False,
                "monitor": monitor,
                "searchForCutoffUnmetEpisodes": False,
                "searchForMissingEpisodes": search_for_missing_episodes
            },
            "rootFolderPath": root_folder,
            "qualityProfileId": quality_profile_id,
            "languageProfileId": language_profile_id
        }

        payload.update(additional_fields)

        response = requests.post(add_url, verify=sonarr_instance.ssl, json=payload, headers={"x-api-key": sonarr_instance.api_key})
        return response.status_code in (200, 201)


def add_radarr_movie(radarr_instance: darr_instance, tvdb_id: int, monitor: str="movieOnly", search_for_missing_movie: bool=True, quality_profile_id: int=1, root_folder: str="/movies") -> bool:
    url = radarr_instance.scheme + "://" + radarr_instance.hostname + ":" + str(radarr_instance.port) + radarr_instance.path + "/api/v3/movie/lookup?term=" + quote("tmdb:" + str(tvdb_id))

    response = requests.get(url, verify=radarr_instance.ssl, headers={"x-api-key": radarr_instance.api_key})
    if response.status_code == 200:
        payload = response.json()
        if len(payload) != 1:
            return False
        
        payload = payload[0]

        add_url = radarr_instance.scheme + "://" + radarr_instance.hostname + ":" + str(radarr_instance.port) + radarr_instance.path + "/api/v3/movie"

        additional_fields = {
            "addOptions": {         
                "monitor": monitor,
                "searchForMovie": search_for_missing_movie,
                "ignoreEpisodesWithFiles": False,
                "ignoreEpsidesWithoutFiles": False
            },
            "monitored": True,
            "rootFolderPath": root_folder,
            "qualityProfileId": quality_profile_id,
        }

        payload.update(additional_fields)

        response = requests.post(add_url, verify=radarr_instance.ssl, json=payload, headers={"x-api-key": radarr_instance.api_key})
        return response.status_code in (200, 201)



def add_custom_quality_profile(darr_instance: darr_instance, json_profile: str):
    url = darr_instance.scheme + "://" + darr_instance.hostname + ":" + str(darr_instance.port) + darr_instance.path + "/api/v3/customformat"
    json_data = json.loads(json_profile)

    updated_fields = {
    "order": 0,
    "name": "value",
    "label": "Language",
    "helpText": "Custom Format RegEx is Case Insensitive",
    "type": "textbox",
    "advanced": False,
    "privacy": "normal",
    "isFloat": False
    }

    for item in json_data["specifications"]:
        item["fields"].update(updated_fields)
        item["fields"] = [item["fields"]]
        



    response = requests.post(url, json=json_data, verify=False, headers={"x-api-key": darr_instance.api_key})


    return response.status_code in (200, 201)

def add_custom_formats(sonarr_instance: darr_instance, radarr_instance: darr_instance) -> bool:
    sonarr_json_files = glob.glob("sonarr_profiles" + os.sep + "*.json")
    radarr_json_files = glob.glob("radarr_profiles" + os.sep + "*.json")

    sonarr_profiles = requests.get(sonarr_instance.scheme + "://" + sonarr_instance.hostname + ":" + str(sonarr_instance.port) + sonarr_instance.path + "/api/v3/customformat", verify=False, headers={"x-api-key": sonarr_instance.api_key}).json()
    sonarr_profiles = [x["name"] for x in sonarr_profiles]

    radarr_profiles = requests.get(radarr_instance.scheme + "://" + radarr_instance.hostname + ":" + str(radarr_instance.port) + radarr_instance.path + "/api/v3/customformat", verify=False, headers={"x-api-key": radarr_instance.api_key}).json()
    radarr_profiles = [x["name"] for x in radarr_profiles]







    for profile in sonarr_json_files:
        with open(profile, 'r') as f:
            content = f.read()
            json_data = json.loads(content)
            if json_data["name"] in sonarr_profiles:
                continue
            add_custom_quality_profile(sonarr_instance, content)
    
    for profile in radarr_json_files:
        with open(profile, 'r') as f:
            content = f.read()
            json_data = json.loads(content)
            if json_data["name"] in radarr_profiles:
                continue
            add_custom_quality_profile(radarr_instance, content)

    return True

def add_quality_profile(darr_instance: darr_instance, json_profile: dict) -> bool:
    url = darr_instance.scheme + "://" + darr_instance.hostname + darr_instance.path + "/api/v3/qualityprofile"
    json_data = json_profile

    response = requests.post(url, json=json_data, verify=False, headers={"X-Api-Key": darr_instance.api_key})
    return response.status_code in (200, 201, 409)

def add_quality_profiles(sonarr_instance: darr_instance, radarr_instance: darr_instance) -> bool:
    sonarr_json_files = glob.glob("sonarr_profiles" + os.sep + "quality_profiles" + os.sep + "*.json")
    radarr_json_files = glob.glob("radarr_profiles" + os.sep + "quality_profiles" + os.sep + "*.json")

    custom_formats_sonarr = requests.get(sonarr_instance.scheme + "://" + sonarr_instance.hostname + ":" + str(sonarr_instance.port) + sonarr_instance.path + "/api/v3/customformat", verify=False, headers={"Authorization": sonarr_instance.api_key}).json()
    custom_formats_sonarr_index = {k["name"]: k["id"] for k in custom_formats_sonarr}

    custom_formats_radarr = requests.get(radarr_instance.scheme + "://" + radarr_instance.hostname + ":" + str(radarr_instance.port) + radarr_instance.path + "/api/v3/customformat", verify=False, headers={"Authorization": radarr_instance.api_key}).json()
    custom_formats_radarr_index = {k["name"]: k["id"] for k in custom_formats_radarr}

    for qp in sonarr_json_files:
        with open(qp) as f:
            sonarr_json = json.loads(f.read())
        for profile in sonarr_json:
            current_formats = set()
            for format in profile['formatItems']:
                current_formats.add(format["name"])
                if format["name"] in custom_formats_sonarr_index:
                    format['format'] = custom_formats_sonarr_index[format["name"]]

            for format, format_id in custom_formats_sonarr_index.items():
                if format not in current_formats:
                    profile["formatItems"].append({"format": format_id, "name": format,"score": 0})

        add_quality_profile(sonarr_instance, sonarr_json[0])

    for qp in radarr_json_files:
        with open(qp) as f:
            radarr_json = json.loads(f.read())
        for profile in radarr_json:
            current_formats = set()
            for format in profile['formatItems']:
                current_formats.add(format["name"])
                if format["name"] in custom_formats_radarr_index:
                    format['format'] = custom_formats_radarr_index[format["name"]]

            for format, format_id in custom_formats_radarr_index.items():
                if format not in current_formats:
                    profile["formatItems"].append({"format": format_id, "name": format,"score": 0})

        add_quality_profile(radarr_instance, radarr_json[0])

    return True

def configure_all_apps(vars):

    traefik_port = ("443" if vars["default_scheme"] == "https" else "80")
    sonarr, lidarr, radarr, bazarr, readarr, prowlarr_instance, prowlarr_internal_instance, radarr_internal_instance, sonarr_internal_instance = [None] * 9

    
    if customisation_params["url_mode"] == "path":
        sonarr = darr_instance("sonarr", vars['hostname'], vars['port'], "/sonarr", True, True, vars['apikey'], vars['default_scheme'], 8989, 9898, "sonarr", "http")
        lidarr = darr_instance("lidarr", vars['hostname'], vars['port'], "/lidarr", True, True, vars['apikey'], vars['default_scheme'], 8686, 6969, "lidarr", "http")
        radarr = darr_instance("radarr", vars['hostname'], vars['port'], "/radarr", True, True, vars['apikey'], vars['default_scheme'], 7878, 6969, "radarr", "http")
        bazarr = darr_instance("bazarr", vars['hostname'], vars['port'], "/bazarr", True, True, vars['apikey'], vars['default_scheme'], 8989, 6969, "bazarr", "http")
        readarr = darr_instance("readarr", vars['hostname'], vars['port'], "/readarr", True, True, vars['apikey'], vars['default_scheme'], 8787, 6969, "readarr", "http")
        prowlarr_instance = darr_instance("prowlarr", vars['hostname'], vars['port'], "/prowlarr", True, True, vars['apikey'], vars['default_scheme'], 9696, 6969, "prowlarr", "http")
        prowlarr_internal_instance = darr_instance("prowlarr_internal", "prowlarr", 9696, "/prowlarr", False, False, vars['apikey'], "http", 9696, 6969, "prowlarr", "http")
    elif customisation_params["url_mode"] == "domain":
        sonarr = darr_instance("sonarr", "sonarr." + vars['hostname'], vars['port'], "", True, True, vars['apikey'], vars['default_scheme'], 8989, 9898, "sonarr", "http")
        lidarr = darr_instance("lidarr", "lidarr." + vars['hostname'], vars['port'], "", True, True, vars['apikey'], vars['default_scheme'], 8686, 6969, "lidarr", "http")
        radarr = darr_instance("radarr", "radarr." + vars['hostname'], vars['port'], "", True, True, vars['apikey'], vars['default_scheme'], 7878, 6969, "radarr", "http")
        bazarr = darr_instance("bazarr", "bazarr." + vars['hostname'], vars['port'], "", True, True, vars['apikey'], vars['default_scheme'], 8989, 6969, "bazarr", "http")
        readarr = darr_instance("readarr", "readarr." + vars['hostname'], vars['port'], "", True, True, vars['apikey'], vars['default_scheme'], 8787, 6969, "readarr", "http")
        prowlarr_instance = darr_instance("prowlarr", "prowlarr." + vars['hostname'], vars['port'], "", True, True, vars['apikey'], vars['default_scheme'], 9696, 6969, "prowlarr", "http")
        prowlarr_internal_instance = darr_instance("prowlarr_internal", "prowlarr", 9696, "", False, False, vars['apikey'], "http", 9696, 6969, "prowlarr", "http")



    darr_set_authentication(prowlarr_instance, "Prowlarr", customisation_params["instance_name"], customisation_params["instance_name"])
    darr_set_authentication(sonarr, "Sonarr", customisation_params["instance_name"], customisation_params["instance_name"], "none", api_version="v3")
    darr_set_authentication(lidarr, "Lidarr", customisation_params["instance_name"], customisation_params["instance_name"], "none", api_version="v1")
    darr_set_authentication(radarr, "Radarr", customisation_params["instance_name"], customisation_params["instance_name"], "none", api_version="v3")

    
    darr_add_download_client(sonarr, "Deluge", "deluge", 8112, customisation_params["torrent_path"], None ,"deluge", implementation="Deluge")
    darr_add_download_client(lidarr, "Deluge", "deluge", 8112, customisation_params["torrent_path"], None ,"deluge", implementation="Deluge", api_version="v1")
    darr_add_download_client(radarr, "Deluge", "deluge", 8112, customisation_params["torrent_path"], None ,"deluge", implementation="Deluge")
    darr_add_download_client(readarr, "Deluge", "deluge", 8112, customisation_params["torrent_path"], None ,"deluge", implementation="Deluge", api_version="v1")
    darr_add_download_client(prowlarr_instance, "Deluge", "deluge", 8112, customisation_params["torrent_path"], None ,"deluge", implementation="Deluge", api_version="v1")

    darr_add_root_folder(sonarr, "/tv/", "/tv/")
    darr_add_root_folder(lidarr, "/music/", "/music/", api_version="v1", additional_fields={"defaultMetadataProfileId": "1", "defaultQualityProfileId": "1", "defaultTags": []})
    darr_add_root_folder(radarr, "/movies", "/movies")
    darr_add_root_folder(readarr, "/books/", "/books/", additional_fields={"defaultMetadataProfileId": "1", "defaultQualityProfileId": "1", "defaultTags": [], "host": "localhost", "isCalibreLibrary": False, "outputProfile": "default", "port": 8080, "useSsl": False}, api_version="v1")

    bazarr_configure_english_providers(bazarr, vars['open_subtitles_username'], vars['open_subtitles_password'])
    bazarr_configure_sonarr_provider(bazarr, sonarr)
    bazarr_configure_radarr_provider(bazarr, radarr)
    bazarr_configure_lang_profile(bazarr)

    ombi = None
    if customisation_params["url_mode"] == "path":
        ombi = ombi_instance(vars["hostname"], traefik_port, customisation_params["ombi_path"], vars["apikey"], scheme=vars['default_scheme'])
    else: 
        ombi = ombi_instance("ombi." + vars["hostname"], traefik_port, customisation_params["ombi_path"], vars["apikey"], scheme=vars['default_scheme'])
    if "plex_username" in vars and "plex_password" in vars:
        ombi_initial_setup(ombi.hostname, traefik_port, customisation_params["ombi_path"], plex_username=vars["plex_username"], plex_password=vars["plex_password"],  api_key=vars["apikey"], scheme=vars["default_scheme"], validate_certificates=False,  local_username=vars["app_username"], local_password=vars["app_password"])
    else:
        ombi_initial_setup(ombi.hostname, traefik_port, customisation_params["ombi_path"], api_key=vars["apikey"], scheme=vars["default_scheme"], validate_certificates=False,  local_username=vars["app_username"], local_password=vars["app_password"])
    ombi_upload_sonarr_profiles(ombi, "sonarr", 8989, True, vars["apikey"], False, customisation_params["sonarr_path"], 4, 1, 1, 1)
    ombi_upload_radarr_profiles(ombi, "radarr", 7878, vars["apikey"], False, customisation_params["radarr_path"], 4, "/movies")
    ombi_upload_lidarr_profiles(ombi, "lidarr", 8686, vars["apikey"], False, customisation_params["lidarr_path"], "/music/")



    darr_add_tag(sonarr, "nohdr", validate_cert=False)

    darr_add_release_profile(sonarr, "Ignore HDR", None, ["\\batmost\\b/i", "/HDR ^|\b(HDR(10\+?)?|dv|dovi|atmos|dolby[-_. ]?vision|HLG)\b/i"], None, ["nohdr"], False)
    darr_add_release_profile(sonarr, "Optionals", None, ["/^(?=.*(1080|720))(?=.*((x|h)[ ._-]?265|hevc)).*/i"], None, None, False)

    if os.path.exists("preferred.json"):
        with open("preferred.json", "r") as preferred_file:
            preferred_json = json.load(preferred_file)
            sonarr_preferred_streaming = preferred_json["sonarr_preferred_streaming"]
            sonarr_preferred_p2p = preferred_json["sonarr_preferred_p2p"]
            sonarr_preferred_lowquality = preferred_json["sonarr_preferred_lowquality"]
            darr_add_release_profile(sonarr, "Streaming Services", None, None, sonarr_preferred_streaming, None, False)
            darr_add_release_profile(sonarr, "P2P-Repack-Proper", None, None, sonarr_preferred_p2p, None, False)
            darr_add_release_profile(sonarr, "Low Quality", None, None, sonarr_preferred_lowquality, None, False)
            if customisation_params["preferr_dv"]:
                darr_add_release_profile(sonarr, "Prefer DV then HDR", None, None, preferred_json["prefer_dv"], ["1"], validate_cert=False)

    if os.path.exists("preload.json"):
        with open("preload.json", "r") as preload_file:
            preload_json = json.load(preload_file)
            if "shows" in preload_json:
                show_dicts = preload_json["shows"]
                for item in show_dicts:
                    add_sonarr_show(sonarr, item["tvdb_id"], 
                                    item["monitor"] if "monitor" in item else "all",
                                    quality_profile_id=item["quality_id"] if "quality_id" in item else 1)
            if "movies" in preload_json:
                movie_dicts = preload_json["movies"]
                for item in movie_dicts:
                    add_radarr_movie(radarr, item["tmdb_id"],
                                    item["monitor"] if "monitor" in item else "movieOnly",
                                    quality_profile_id=item["quality_id"] if "quality_id" in item else 1)
                    
    if os.path.exists("sonarr_profiles") and os.path.exists("radarr_profiles"):
        add_custom_formats(sonarr, radarr)
    
    if os.path.exists("sonarr_profiles" + os.sep + "quality_profiles") and os.path.exists("radarr_profiles" + os.sep + "quality_profiles"):
        add_quality_profiles(sonarr, radarr)


    indexers = prowlarr_get_all_public_indexers(prowlarr_instance, False, prowlarr_instance.api_key)
    prowlarr_add_indexers(prowlarr_instance, False, prowlarr_instance.api_key, indexers)
    prowlarr_add_radarr(prowlarr_instance, radarr, prowlarr_internal_instance)
    prowlarr_add_sonarr(prowlarr_instance, sonarr, prowlarr_internal_instance)
    prowlarr_add_readarr(prowlarr_instance, readarr, prowlarr_internal_instance)
    prowlarr_add_lidarr(prowlarr_instance, lidarr, prowlarr_internal_instance)
    prowlarr_add_flaresolverr(prowlarr_instance, validate_ssl=customisation_params["validate_ssl"], flaresolverr_hostname="flaresolverr", flaresolverr_port=8191)
   

    




def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--hostname", required=True, help="IP Address/Hostname of the *arr clients")
    parser.add_argument("-p", "--port", required=True, help="Port of the *arr clients")
    parser.add_argument("-a", "--apikey", required=True, help="IP Address of the *arr clients")
    parser.add_argument("-s", "--default-scheme", required=False, choices=["http", "https"], default="http", help="Default scheme")
    parser.add_argument("--open-subtitles-username", help="OpenSubtitles.org.com username")
    parser.add_argument("--open-subtitles-password", help="OpenSubtitles.org.com password")
    parser.add_argument("--plex-username", help="Plex username")
    parser.add_argument("--plex-password", help="Plex password")
    parser.add_argument("--app-username", help="Username for apps when required")
    parser.add_argument("--app-password", help="Password for apps when required")
    args = vars(parser.parse_args())

    configure_all_apps(args)
    print("success")

main()