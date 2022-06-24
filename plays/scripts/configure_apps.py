
import threading
import requests, json, argparse


import urllib3

urllib3.disable_warnings()


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

def heimdall_add_items(scheme: str, hostname: str, port: int, heimdall_path: str, api_key, validate_certs: bool=False):
    url = scheme  + "://" + hostname + ":" + str(port) + heimdall_path

    heimdall_session = requests.Session()

    ombi_fields = {
        "appid": "57b25ceb94bd4c9ba9038ce17656f5ede9007e4c",
        "title": "Ombi",
        "colour": "#161b1f",
        "url": scheme + "://" + hostname + ":" + str(port) + heimdall_path + "/ombi",
        "tags[]": 0,
        "icon": "https://appslist.heimdall.site/icons/ombi.png",
        "appdescription": "Ombi - Media Requests",
        "config[enabled]": 1,
        "config[override_url]": scheme + "://" + hostname + ":" + str(port) + heimdall_path + "/ombi",
        "pinned": 1,
        "website": None,
        "config[apikey]": api_key
    }


    response = heimdall_session.post(url + "items", data=ombi_fields, verify=validate_certs)
    return response.status_code == 200

def make_post_request(url, json_body, headers, verify):
    resp = requests.post(url, json=json_body, headers=headers, verify=verify)
    print(resp)

def darr_add_all_configured_jacket_indexers(darr: darr_instance, jackett_api_key, jackett_scheme, jackett_hostname: str, jackett_port: int, jackett_path, int_jackett_scheme, int_jackett_hostname, int_jackett_port, int_jackett_path, validate_certs=False, categories=[5030, 5040], api_version="v3"):
    url = jackett_scheme + "://" + jackett_hostname + ":" + str(jackett_port) + jackett_path + "/api/v2.0/indexers/?configured=true"
    response_json = requests.get(url, verify=validate_certs).json()
    
    current_darr_indexers = requests.get(f"{darr.scheme}://{darr.hostname}:" + str(darr.port) + darr.path + "/api/" + api_version + "/indexer", headers={"x-api-key" : darr.api_key}, verify=validate_certs).json()
    darr_indexers = [x["name"] for x in current_darr_indexers]

    threads = []

    for indexer in response_json:
        indexer_dict = {}
        indexer_dict["id"] = indexer["id"]

        if indexer_dict["id"] in darr_indexers:
            continue
        cap_matches = [x["ID"] for x in indexer["caps"] if int(x["ID"]) in categories]
        if len(cap_matches) < 1:
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

        th = threading.Thread(target=make_post_request, args=(url, body, {"x-api-key" : darr.api_key}, validate_certs,))
        threads.append(th)
        th.start()

    for thread in threads:
        thread.join()





        


#torznab_url = jackett_scheme + "://" + jackett_hostname + ":" + str(jackett_port) + "/jackett/api/v2.0/indexers/{id}/results/torznab".format(id)

def configure_all_apps(vars):


    sonarr = darr_instance(vars['hostname'], vars['port'], "/sonarr", True, True, vars['apikey'], "https")
    lidarr = darr_instance(vars['hostname'], vars['port'], "/lidarr", True, True, vars['apikey'], "https")
    radarr = darr_instance(vars['hostname'], vars['port'], "/radarr", True, True, vars['apikey'], "https")
    bazarr = darr_instance(vars['hostname'], vars['port'], "/bazarr", True, True, vars['apikey'], "https")
    readarr = darr_instance(vars['hostname'], vars['port'], "/readarr", True, True, vars['apikey'], "https")

    
    darr_add_download_client(sonarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge")
    darr_add_download_client(lidarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge", api_version="v1")
    darr_add_download_client(radarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge")
    darr_add_download_client(readarr, "Deluge", "deluge", 8112, "/", None ,"deluge", implementation="Deluge", api_version="v1")

    darr_add_root_folder(sonarr, "/tv/", "/tv/")
    darr_add_root_folder(lidarr, "/music/", "/music/", api_version="v1", additional_fields={"defaultMetadataProfileId": "1", "defaultQualityProfileId": "1", "defaultTags": []})
    darr_add_root_folder(radarr, "/movies", "/movies/", api_version="v1")
    darr_add_root_folder(readarr, "/books/", "/books/", additional_fields={"defaultMetadataProfileId": "1", "defaultQualityProfileId": "1", "defaultTags": [], "host": "localhost", "isCalibreLibrary": False, "outputProfile": "default", "port": 8080, "useSsl": False}, api_version="v1")

    bazarr_configure_english_providers(bazarr, vars['open_subtitles_username'], vars['open_subtitles_password'])
    bazarr_configure_sonarr_provider(bazarr, sonarr)
    bazarr_configure_radarr_provider(bazarr, radarr)
    bazarr_configure_lang_profile(bazarr)

    darr_add_all_configured_jacket_indexers(sonarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "",categories=[5030, 5040, 5000, 5010, 5020, 5045, 5050, 5060, 5070, 5080])
    darr_add_all_configured_jacket_indexers(radarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "", categories=[2000,2010,2020, 2030, 2040,2050,2060, 2070, 2080])
    darr_add_all_configured_jacket_indexers(readarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "", categories=[3030, 7020, 8010], api_version="v1")
    darr_add_all_configured_jacket_indexers(lidarr, vars["apikey"],"https", vars["hostname"], 443, "/jackett", "http", "jackett", 9117, "",categories=[3000,3010,3020,3030,3040], api_version="v1")




def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--hostname", required=True, help="IP Address/Hostname of the *arr clients")
    parser.add_argument("-p", "--port", required=True, help="Port of the *arr clients")
    parser.add_argument("-a", "--apikey", required=True, help="IP Address of the *arr clients")
    parser.add_argument("--open-subtitles-username", help="OpenSubtitles.org/.com username")
    parser.add_argument("--open-subtitles-password", help="OpenSubtitles.org/.com password")
    args = vars(parser.parse_args())

    configure_all_apps(args)
    print("success")

main()
