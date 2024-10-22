#!/usr/bin/env python3
import yaml, argparse



def main():
    with open("/home/docker/docker_data/bazarr/config/config/config.yaml", "r+") as yaml_file:
        bazarr = yaml.safe_load(yaml_file)
        yaml_file.seek(0)

        parser = argparse.ArgumentParser()
        parser.add_argument("--apikey")
        args = parser.parse_args()

        if args.apikey is not None:
            bazarr["general"]["apikey"] = args.apikey
            bazarr["sonarr"]["apikey"] = args.apikey
            bazarr["radarr"]["apikey"] = args.apikey

        bazarr["general"]["base_url"] = "/bazarr"
        bazarr["sonarr"]["base_url"] = "/sonarr"
        bazarr["radarr"]["base_url"] = "/radarr"



        yaml.dump(bazarr, yaml_file)
        yaml_file.truncate()

if __name__ == '__main__':
    main()
    print("Updated bazarr base URL's")
