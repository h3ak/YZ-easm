import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Request:
    @staticmethod
    def disable_insecure_request_warning():
        print('1')