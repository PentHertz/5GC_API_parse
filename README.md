# 5GC_API_parse

## Description

5GC API parse is a BurpSuite extension allowing to assess 5G core network network function, by parsing the OpenAPI 3.0 not supported by previous OpenAPI extension in Burp, and generating requests for intrusion tests purposes.

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

- `git clone 'https://github.com/PentHertz/5GC_API_parse.git' <installation_folder>`
- Open Burp on Extender/ Extensions
- Click `Add`
- Set Extension type as Python
- Set Extension file to `<installation_folder>/5GC_API_parse.py`
- Click `Next`
- The addon is now installed, a new tab named `5GC API parse` should appear


## Usage

Just provide a target address with URL scheme, a port number and a OpenAPI 3.0 file you want to process and voilà:

![Burp extension's tab](https://github.com/PentHertz/5GC_API_parse/blob/main/images/parsedfile.png)

You are ready to use it in the repeater, intruder to fuzz, etc.
