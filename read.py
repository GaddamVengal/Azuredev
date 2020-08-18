from robot.api import logger
try:
    import requests
    import json
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception as ex:
    logger.info("Exception :"+str(ex))
class read(object):
    '''
        This class is used to read secrets from Azure key vault
    '''
    def run(self, vaultkey, vaultdetails, aedatastore):
        '''
        This method is used to read secrets from Azure key vault
        '''
        try:
            vault_entity_name = vaultkey.split("/")[2]
            client_secret = aedatastore["azurevault_client_secret_AzureVault"]
            client_id = vaultdetails['vault']['azclientid']
            tenant = vaultdetails['vault']['aztenantid']
            resource='https://vault.azure.net'
            url='https://login.microsoftonline.com/'+tenant+'/oauth2/v2.0/token'
            headers={"Content-Type":"application/x-www-form-urlencoded"}
            body={"grant_type": "client_credentials", "client_id": client_id,"client_secret": client_secret,"scope":"https://vault.azure.net/.default"}
            response = requests.post(url, headers=headers, data=body, verify=False, timeout=10)
            if response.status_code == 200:
                result= json.loads(response.text)
                access_token = result["access_token"]
                result["status"] = True
                result["access_token"] = access_token
            else:
               if response.text :
                    err = json.loads(response.text)
                    return (False, str(err['error']['message']))
               else:
                    return (False, "Unable to fetch Token from Azure key vault,\
                            status code = "+str(response.status_code))
            vault_name = vaultdetails['vault']['azvaultname']
            secret_id = vaultkey.split('/')[4]
            access_token="Bearer " + result['access_token']
            headers = {"Authorization":access_token}
            url = 'https://'+vault_name+'.vault.azure.net/secrets/'+secret_id+'/?api-version=2016-10-01'
            result = requests.get(url, headers=headers, data= access_token,  verify=False)
            if result.status_code == 200:
                output = json.loads(result.text)
                encrypted_pwd = str(output['value'])
                return (True, encrypted_pwd)
            else:
               if result.text :
                    err = json.loads(result.text)
                    return (False, str(err['error']['message']))
               else:
                    return (False, "Unable to fetch Password from Azure key vault,\
                            status code = "+str(result.status_code))
        except Exception as excep:
            return (False, "Unable to fetch Password from Azure key vault, Error:"+str(excep))

