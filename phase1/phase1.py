import json
import os
import sys
from scrapy.crawler import CrawlerProcess
from project.spiders.test import TestSpider
from scrapy.utils.project import get_project_settings

output_urls = []


def remove_files(file_name):

    try:
        os.remove("items.json")
        os.remove(file_name)
        pass
    except OSError:
        pass


def read_config(run_name):
    with open('../config.json') as config_file:
        config_inputs = json.load(config_file)["loginurls"]
        for config_input in config_inputs:
            if config_input["name"] == run_name:
                print config_input["password_field"]
                return{"start_url": config_input["start_url"],
                       "login_page": config_input["login_page"],
                       "login_url": config_input["loginurl"],
                      "domain": config_input["domain"],
                      "ignore_params": config_input["ignore_params"],
                      "username": config_input["loginpayload"][config_input["username_field"]],
                      "password": config_input["loginpayload"][config_input["password_field"]],
                      "username_field": config_input["username_field"],
                      "password_field": config_input["password_field"]}

        raise NameError('Invalid config name')


def crawler_execution(crawler_config):
    settings = get_project_settings()
    process = CrawlerProcess(settings)

    process.crawl(TestSpider,
                  start_url=crawler_config["start_url"],
                  domain=crawler_config["domain"],
                  login_page=crawler_config["login_page"],
                  login_url=crawler_config["login_url"],
                  username=crawler_config["username"],
                  password=crawler_config["password"],
                  username_field=crawler_config["username_field"],
                  password_field=crawler_config["password_field"],
                  ignore_params=crawler_config["ignore_params"])
    process.start()  # the script will block here until the crawling is finished


def reformat_output():
    with open("items.json") as my_file:
        urls = json.load(my_file)
        for item in urls:
            if item not in output_urls:
                output_urls.append(item)


def write_to_file(output_file):
    print "-----------total number of links------------"
    print len(output_urls)
    phase1_file = open(output_file, 'w')
    output = {"urls": output_urls}
    phase1_file.write(json.dumps(output))


run_name = sys.argv[1:][0]
output_file = "../results/" + run_name + ".json"

remove_files(output_file)
crawler_config = read_config(run_name)

crawler_execution(crawler_config)
reformat_output()


write_to_file(output_file)

