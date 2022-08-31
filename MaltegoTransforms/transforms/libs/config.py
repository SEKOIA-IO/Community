import yaml

file = open("config.yaml")
config = yaml.load(file, Loader=yaml.FullLoader)