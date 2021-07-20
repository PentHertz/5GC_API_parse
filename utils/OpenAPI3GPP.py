#
#   Part of the 5GC API Parse
#   A 5GC NF OpenAPI parser -  Burp Suite Extension
#   Author: Sebastien Dudek (@FlUxIuS) at https://penthertz.com
#
import yaml
import json

class OpenAPI3GPP(object):
    

    yamlinst = None


    def __init__(self, yamlfile):
        self.yamlinst = yaml.load(open(yamlfile), Loader=yaml.FullLoader)


    def listpaths(self):
        return [k for k, v in self.yamlinst['paths'].items()]

    
    def getEndPointVerbs(self, path):
        return [k for k, v in self.yamlinst['paths'][path].items()]


    def getEndPointSummary(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['summary']
        except:
            return None


    def getTags(self, path, verb):
        try:
            return ''.join(self.yamlinst['paths'][path][verb]['tags'])
        except:
            return None


    def getParameters(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['parameters']
        except:
            return []


    def getRequestBody(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['callbacks']
        except:
            return []


    def dumpParameters(self, path, verb):
        try:
            return yaml.dump(self.getParameters(path, verb))
        except:
            return None


    def dumpRequestBody(self, path, verb):
        try:
            return yaml.dump(self.getRequestBody(path, verb))
        except:
            return None


    def getRequestJSObject(self, path, verb):
        try:
            return self.yamlinst['paths'][path][verb]['requestBody']['content']['application/json']['schema']['$ref']
        except:
            return None


    def fetchObject(self, path):
        prop = self.yamlinst
        for k in path:
            prop = prop[k]
        return prop


    def getPropJSObject(self, path, verb):
        jsobj = self.getRequestJSObject(path, verb)
        paths = jsobj.split('/')[1:]
        obj = self.fetchObject(paths)
        required = obj['required']
        return (obj['properties'], required) 


    def buildJSObj(self, path, verb):
        props, reqs = self.getPropJSObject(path, verb)
        ojson = {}
        for k, v in props.items():
            if k in reqs:
                ojson[k] = 'required_value'
            else:
                ojson[k] = 'value'
        return repr(ojson)


    # default field values
    field_table = { 'Content-Encoding' : 'gzip, deflate',
                    'Accept-Encoding' : 'gzip, deflate',
                    'User-Agent' : 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0',
                    'Accept' : 'application/json',
    }


    def buildDefaultHeaders(self, netloc):
        string = ""
        string += 'Host: ' + netloc + "\r\n"
        string += 'User-Agent: ' + self.field_table['User-Agent'] + "\r\n"
        string += 'Accept: ' + self.field_table['Accept'] + "\r\n"
        return string


    def buildRequest(self, path, verb, reqpath, netloc):
        """
            Builds web request from YAML file
        """
        parameters = self.getParameters(path, verb)
        reqpath = self.yamlinst['servers'][0]['url'].format(apiRoot=reqpath) + path
        extrpath = ""
        headers = self.buildDefaultHeaders(netloc)
        body = "\r\n"
        reqstring = "{verb} {path} HTTP/1.1\r\n"
        for param in parameters:
            try:
                value = "{value}"
                if param['name'] in self.field_table:
                    value = self.field_table[param['name']]

                if param['in'] == 'header':
                    headers += "%s: %s\r\n" % (param['name'], value)
                elif param['in'] == 'query':
                    if extrpath == '':
                        extrpath += "?"
                    required = ''
                    if 'required' in param:
                        if param['required'] == True:
                            required = "required"
                    extrpath += "%s=%s&" % (param['name'], required)
            except:
                pass
        reqpath += extrpath[:-1] # delete last and op
        reqstring = reqstring.format(verb=verb.upper(), path=reqpath)
        reqstring += headers
        reqstring += "\n"
        reqObj = self.getRequestJSObject(path, verb)
        if reqObj is not None:
            reqstring += "\n"
            reqstring += self.buildJSObj(path, verb)
        return reqstring
