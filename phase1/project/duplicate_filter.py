import os

from scrapy.dupefilter import RFPDupeFilter
from scrapy.utils.request import request_fingerprint


class CustomFilter(RFPDupeFilter):

    def __should_ignore(self, request, fp):
        if request.meta and ("ignore_params" in request.meta.keys()):
            ignore_params = request.meta["ignore_params"]
            for ignore_param in ignore_params:
                if ignore_param in fp:
                    return True

        return False

    def request_seen(self, request):
        fp = request.method + " " + request.url
        if fp in self.fingerprints:
            return True
        if self.__should_ignore(request, fp):
            return True

        self.fingerprints.add(fp)
        if self.file:
            self.file.write(fp + os.linesep)
