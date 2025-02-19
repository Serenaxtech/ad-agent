import configReader

config_test = configReader.Config(config_file= '../config.ini')
config_json = config_test.parseToJson()
print(type(config_json))