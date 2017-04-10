import scrapy
from scrapy.linkextractors import LinkExtractor
import urlparse
from project.items import ProjectItem
from scrapy.http import Request
from scrapy.spiders.init import InitSpider
import fill_form
from find_login_form import get_form_data

class TestSpider(InitSpider):
    name = "test"
    login_required = False

    link_extractor = {
        'next_page': LinkExtractor(allow=(), restrict_css=('a'))
    }

    login_item = None

    def __init__(self, *args, **kwargs):
        super(TestSpider, self).__init__(*args, **kwargs)

        self.start_urls = [kwargs.get('start_url')]
        self.allowed_domains = [kwargs.get('domain')]
        self.login_page = kwargs.get('login_page')
        self.username = kwargs.get('username')
        self.password = kwargs.get('password')
        self.username_field = kwargs.get('username_field')
        self.password_field = kwargs.get('password_field')
        self.ignore_params = kwargs.get('ignore_params')

    def init_request(self):
        print "-------------initialize---------------"
        if self.username != "" and self.password != "":
            return Request(url=self.login_page, callback=self.login)
        return self.initialized()

    def login(self, response):
        form_data, action = get_form_data(response.body, response.url, self.username_field, self.password_field, self.username, self.password)
        self.login_item = self.generate_login_item(form_data, action)

        return scrapy.FormRequest(action,
                                formdata=form_data,
                                callback=self.check_login_response)

    def check_login_response(self, response):
        if "logout" in response.body.lower():
            self.log("Successfully logged in. Let's start crawling!")
            # Now the crawling can begin..
            self.login_required = True
            return self.initialized()
        else:
            self.log("Bad times :(")
            # Something went wrong, we couldn't log in, so nothing happens.

    def parse(self, response):
        if self.login_item:
            yield self.login_item

        post_forms = fill_form.fetch_form(response.url, response.body)
        for post_form in post_forms:
            post_item = self.generate_post_item(post_form)
            if post_item is not None:
                yield post_item
                # yield scrapy.FormRequest(post_item["url"],
                #                    formdata=post_item["param"],
                #                    callback=self.parse)

        yield self.generate_get_item(response)

        # Find links to the next page
        for link in self.link_extractor['next_page'].extract_links(response):
            if "http" not in link.url:
                continue
            if "logout" in link.url or "delete" in link.url:
                yield self.generate_get_item_with_no_response(link.url)
                continue
            if link.url.endswith(".jpg"):
                continue

            yield Request(url=link.url, meta={'ignore_params': self.ignore_params}, callback=self.parse)

    def generate_login_item(self, form_data, action):
        self.login_url = action
        post_item = ProjectItem()
        post_item["url"] = self.login_url

        output_form_data = {}
        for key in form_data.keys():
            output_form_data[key] = [form_data[key]]
        post_item["param"] = output_form_data

        post_item["type"] = "POST"
        post_item["loginrequired"] = "false"
        post_item["loginurl"] = ""
        return post_item

    def generate_post_item(self, post_form):
        post_item = ProjectItem()
        post_item["url"] = post_form["url"]
        post_item["param"] = post_form["fields"]
        post_item["type"] = "POST"
        if self.login_required:
            post_item["loginrequired"] = "true"
            post_item["loginurl"] = self.login_url
        else:
            post_item["loginrequired"] = "false"
            post_item["loginurl"] = ""

        if bool(post_item["param"]):
            return post_item
        return None

    def generate_get_item(self, response):
        parsed = urlparse.urlparse(response.url)
        parameters = urlparse.parse_qs(parsed.query)

        item = ProjectItem()
        url = parsed.geturl()
        if "?" in url:
            item['url'] = url[:url.find('?')]
        else:
            item['url'] = url

        item['param'] = parameters
        item['type'] = "GET"
        if self.login_required:
            item["loginrequired"] = "true"
            item["loginurl"] = self.login_url
        else:
            item["loginrequired"] = "false"
            item["loginurl"] = ""

        referer = None
        if "Referer" in response.request.headers.keys():
            referer = response.request.headers["Referer"]
        item["headers"] = {
            "referer": referer,
            "user-agent": response.request.headers["User-Agent"]
        }
        return item


    def generate_get_item_with_no_response(self, response_url):
        parsed = urlparse.urlparse(response_url)
        parameters = urlparse.parse_qs(parsed.query)

        item = ProjectItem()
        url = parsed.geturl()
        if "?" in url:
            item['url'] = url[:url.find('?')]
        else:
            item['url'] = url

        item['param'] = parameters
        item['type'] = "GET"
        if self.login_required:
            item["loginrequired"] = "true"
            item["loginurl"] = self.login_url
        else:
            item["loginrequired"] = "false"
            item["loginurl"] = ""

        item["headers"] = {}
        return item
