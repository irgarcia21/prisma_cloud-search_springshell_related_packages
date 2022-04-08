from __future__ import print_function
from distutils.log import warn
import json
import requests
import configparser
import os

requests.packages.urllib3.disable_warnings() # Added to avoid warnings in output if proxy

def return_error (message):
    print("\nERROR: " + message)
    exit(1)

def get_parser_from_sections_file (file_name):
    file_parser = configparser.ConfigParser()
    try: # Checks if the file has the proper format
        file_parser.read(file_name)
    except (ValueError, configparser.MissingSectionHeaderError, configparser.DuplicateOptionError, configparser.DuplicateOptionError):
        return_error ("Unable to read file " + file_name)
    return file_parser

def read_value_from_sections_file (file_parser, section, option):
    value={}
    value['Exists'] = False
    if file_parser.has_option(section, option): # Checks if section and option exist in file
        value['Value'] = file_parser.get(section,option)
        if not value['Value']=='': # Checks if NOT blank (so properly updated)
            value['Exists'] = True
    return value

def read_value_from_sections_file_and_exit_if_not_found (file_name, file_parser, section, option):
    value = read_value_from_sections_file (file_parser, section, option)
    if not value['Exists']:
        return_error("Section \"" + section + "\" and option \"" + option + "\" not found in file " + file_name)
    return value['Value']

def load_api_config (iniFilePath):
    if not os.path.exists(iniFilePath):
        return_error("Config file " + iniFilePath + " does not exist")
    iniFileParser = get_parser_from_sections_file (iniFilePath)
    api_config = {}
    api_config['BaseURL'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'URL', 'URL')
    api_config['AccessKey'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'AUTHENTICATION', 'ACCESS_KEY_ID')
    api_config['SecretKey'] = read_value_from_sections_file_and_exit_if_not_found (iniFilePath, iniFileParser, 'AUTHENTICATION', 'SECRET_KEY')
    return api_config

def handle_api_response (apiResponse):
    status = apiResponse.status_code
    if (status != 200):
        return_error ("API call failed with HTTP response " + str(status))

def run_api_call_with_payload (action, url, headers_value, payload):
    apiResponse = requests.request(action, url, headers=headers_value, data=json.dumps(payload), verify=False) # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse

def run_api_call_without_payload (action, url, headers_value):
    apiResponse = requests.request(action, url, headers=headers_value, verify=False) # verify=False to avoid CA certificate error if proxy between script and console
    handle_api_response(apiResponse)
    return apiResponse

def login (api_config):
    action = "POST"
    url = api_config['BaseURL'] + '/api/v21.08/authenticate'
    headers = {
        'Content-Type': 'application/json'
    }
    payload = {
        'username': api_config['AccessKey'],
        'password': api_config['SecretKey'],
    }
    apiResponse = run_api_call_with_payload (action, url, headers, payload)
    authentication_response = apiResponse.json()
    token = authentication_response['token']
    return token

def writeApiData(images):
    myImages = {}
    myPackages = {}
    myPackages['jdk'] = []
    myPackages['tomcat'] = []
    myPackages['war'] = []
    jdk = False
    tomcat = False
    war = False

    for image in images:
    
        if 'packages' in image:
            for packages in image['packages']:
                for pkgs in packages['pkgs']:                  
                    if "jdk" in pkgs['name'] and "java" in pkgs['name']:
                        jdk = True
                        myPackages['jdk'] = addPackage (pkgs, myPackages['jdk'])
                    if "tomcat" in pkgs['name']:
                        tomcat = True
                        myPackages['tomcat'] = addPackage (pkgs, myPackages['tomcat'])
                    if "path" in pkgs:
                        if ".war" in pkgs['path']:
                            war = True
                            myPackages['war'] = addPackage (pkgs, myPackages['war'])
            
            if jdk or tomcat or war:
                myImages[image['_id']] = myPackages

            jdk = False
            tomcat = False
            war = False
                     
    writeFile('out-images', myImages)


def addPackage (pkgs, myPackages):
    if "path" in pkgs:
        myPackages.append ("Name: " + pkgs['name'] + " // Version: " + pkgs['name'] + " // Path: " + pkgs['path'])
    else:
        myPackages.append ("Name: " + pkgs['name'] + " // Version: " + pkgs['name'])
    return myPackages


def writeFile(fileName, data):
    with open(fileName+".json", "w") as outfile:
        outfile.write(json.dumps(data, indent=4))

def main():
    
    #----------- Load API configuration from .ini file -----------

    api_config = load_api_config ("API_config.ini")

    #----------- First API call for authentication -----------

    token = login(api_config)
    api_config['Token'] = token
    
    #----------- Download images -----------

    action = "GET"
    url = api_config['BaseURL'] + "/api/v22.01/images"
    headers = {
        'Authorization': 'Bearer ' + api_config['Token']
    }
    apiResponse = run_api_call_without_payload (action, url, headers)
    images = apiResponse.json()
    writeApiData(images)
    

if __name__ == "__main__":
    main()