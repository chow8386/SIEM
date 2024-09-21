from __future__ import absolute_import
from __future__ import print_function
import splunklib.client as client
import splunklib.results as results

class SplunkSearch:
    def __init__(self,query):
        self.query = query

    def connect_to_splunk(self):
        HOST = "192.168.40.5"
        PORT = 8089
        USERNAME = "admin"
        PASSWORD = "16040312b"

        try: 
            service = client.connect(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD)
            return service
        except Exception as e:
            print(e)
            return None

    def create_seach(self):
        service = self.connect_to_splunk()
        if service:
            try: 
                time_search = {"earliest_time": "-5m"}
                searchquery = self.query
                result = service.jobs.oneshot(searchquery, **time_search)
                reader = results.ResultsReader(result)
                listIp = []
                for i in reader:
                    if i['Source_Network_Address'] in listIp:
                        pass
                    else: 
                        listIp.append(i['Source_Network_Address'])
                return listIp
                    
            except Exception as e:
                print(e)
                return None
