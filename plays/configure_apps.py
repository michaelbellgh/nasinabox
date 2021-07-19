import requests, json, sys

def api_request_darr(hostname: str, port: int, path: str, api_key: str, json: str, scheme: str="https", method: str="POST", verify_certificate=False):
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

def ombi_upload_sonarr_profiles(ombi: ombi_instance, sonarr_hostname: str, sonarr_port: int, v3: bool, sonarr_api_key: str, ssl: bool, base_url: str, quality_profile: int, root_dir: int, language_profile: int):
    fields = {"enabled" : True, "apiKey" : sonarr_api_key, "addOnly" : False, "ip" : sonarr_hostname, "languageProfiles" : language_profile, "port" : str(sonarr_port), "qualityProfile" : quality_profile, "qualityProfileAnime" : quality_profile, "rootPath" : root_dir, "rootPathAnime" : root_dir, "seasonFolders" : True, "ssl" : ssl, "subDir" : base_url, "v3" : v3}
    response = ombi_api_request(ombi, "/api/v1/Settings/Sonarr", body=json.dumps(fields))
    print(response.text)


### *darr Methods

class darr_instance:
    def __init__(self, hostname: str, port: int, path: str, ssl: bool, v3: bool, api_key: str, scheme: str):
        self.hostname = hostname
        self.port = port
        self.path = path
        self.scheme = scheme
        self.ssl = ssl
        self.v3 = v3
        self.api_key = api_key

def darr_add_root_folder(darr : darr_instance, path):
    api_request_darr(darr.hostname, darr.port, darr.path + "/api/v3/rootFolder", darr.api_key, json.dumps({"path" : path}), darr.scheme)

def darr_add_download_client(darr: darr_instance, name: str, torrent_hostname: str, torrent_port: int, torrent_path: str, torrent_username: str, torrent_password: str, implementation: str="Transmission"):
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

    api_request_darr(darr.hostname, darr.port, darr.path + "/api/v3/downloadclient", darr.api_key, body, darr.scheme, "POST")


def darr_add_root_folder(darr: darr_instance, folder: str):
    api_request_darr(darr.hostname, darr.port, darr.path + "/api/v3/rootFolder", darr.api_key, {"path" : folder})

def configure_all_apps(hostname: str, port: int, apikey: str):

    sonarr = darr_instance(hostname, port, "/sonarr", True, True, apikey, "https")
    lidarr = darr_instance(hostname, port, "/lidarr", True, True, apikey, "https")
    radarr = darr_instance(hostname, port, "/radarr", True, True, apikey, "https")

    add_torznab_indexer(hostname, port, "/sonarr", "http://jackett:9117", "Jackett", "/api/v2.0/indexers/all/results/torznab", [5030, 5040], apikey, info_link="https://wiki.servarr.com/Sonarr_Supported_torznab")
    add_torznab_indexer(hostname, port, "/lidarr", "http://jackett:9117", "Jackett", "/api/v2.0/indexers/all/results/torznab", [3000,3010,3020,3030,3040], apikey, custom_fields={"earlyReleaseLimit" : None, "seedCriteria.discographySeedTime" : None}, indexer_api_path="/api/v1/indexer") 
    add_torznab_indexer(hostname, port, "/radarr", "http://jackett:9117", "Jackett", "/api/v2.0/indexers/all/results/torznab", [2000,2010,2020,2030,2040,2050,2060], apikey, custom_fields={"multiLanguages" : [], "removeYear" : False, "requiredFlags" : []}) 
    
    darr_add_download_client(sonarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge")
    darr_add_download_client(lidarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge")
    darr_add_download_client(radarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge")

    darr_add_root_folder(sonarr, "/tv/")
    darr_add_root_folder(lidarr, "/music/")
    darr_add_root_folder(radarr, "/movies/")


    



configure_all_apps(sys.argv[1], int(sys.argv[2]), sys.argv[3])