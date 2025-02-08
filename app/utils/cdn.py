import yaml

cdn_file = "../dict/cdn.yaml"
def readYaml():
    with open(cdn_file, 'r') as file:
        data = yaml.safe_load(file)
        return data

def cdn_check(cname):
    yamlData = readYaml()
    for domain in yamlData.keys():
        if domain in cname:
            return True
    return False

if __name__ == "__main__":
    print(cdn_check("ipsimg-huanan1.oss-cn-shenzhen.aliyuncs.com"))