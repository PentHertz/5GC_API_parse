# 5GC_API_parse

## Description

5GC API parse is a BurpSuite extension allowing to assess 5G core network functions, by parsing the OpenAPI 3.0 not supported by previous OpenAPI extension in Burp, and generating requests for intrusion tests purposes.

![Burp extension's tab](https://raw.githubusercontent.com/PentHertz/5GC_API_parse/main/images/first.png)


## Installation
 
### Jython installation (required) 

- Download Jython 2.7.x Installer Jar from [https://www.jython.org/download]()
- Install Jython by default:

```bash
java -jar jython-installer-2.7.2.jar
```
- Download PyYAML from [https://github.com/yaml/pyyaml]()
- Install PyYAML:

```bash
./jython PyYAML-5.4.1/setup.py install
```
- Open Burp on Extender / Options
- In Python Environment, set the location of the Jython JAR to the installed one

### 5GC API parse

- Set Extension file to `<installation_folder>/5GC_API_parse.py`
- Click `Next`
- The addon is now installed, a new tab named `5GC API parse` should appear


## Usage

Just provide a target address with URL scheme, a port number and a OpenAPI 3.0 file you want to process and voilà:

![Burp extension's tab](https://github.com/PentHertz/5GC_API_parse/blob/main/images/parsedfile.png)

You are ready to use it in the repeater, intruder to fuzz, etc.

Quick demo:

https://user-images.githubusercontent.com/715195/126624333-6c4260e8-361e-4a57-b9b1-0e3c297467f7.mp4

## Change log

- 1.2 (07/20/2021): Core reorganization + adding Swagger browsing for associated YAML files and a clear-all button
- 1.1 (07/20/2021): Fixing errors in headers and adapting default values to actual 5G core
- 1.0 (05/20/2021): Initial release
