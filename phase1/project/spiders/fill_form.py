from lxml import html


def _retrieve_form_element(form, origin_url):
    fields = {}
    for x in form.inputs:
        if x.value is None:
            if type(x) == html.SelectElement:
                x.value = x.value_options[0]
            else:
                x.value = "None"
        if type(x) == html.TextareaElement:
            fields[x.name] = [""]
        elif x.name and ("type" in x.keys() and x.type != "submit") and not ("Fatal error" in x.value):
            fields[x.name] = [x.value]

    url = form.action
    if (url is None) or (url is ""):
        url = origin_url
    return {"fields": fields, "url": url}


def fetch_form(url, body):
    doc = html.document_fromstring(body, base_url=url)
    form_items = []
    for form in doc.xpath('//form'):
        form_items.append(_retrieve_form_element(form, url))
    return form_items
