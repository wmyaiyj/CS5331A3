from lxml import html
from urlparse import urljoin


def get_form_data(response, origin_url, username_field, password_field, username, password):
    doc = html.document_fromstring(response)
    login_form_data = None
    action = None
    for form in doc.xpath('//form'):
        username_field_match = False
        password_field_match = False
        form_data = {}
        for form_input in form.inputs:
            if form_input.name and form_input.type != "submit" and not form_input.checkable:
                form_data[form_input.name] = form_input.value
            if form_input.name == username_field:
                username_field_match = True
            if form_input.name == password_field:
                password_field_match = True

        if username_field_match and password_field_match:
            login_form_data = form_data
            action = urljoin(origin_url, form.action)

    login_form_data[username_field] = username
    login_form_data[password_field] = password

    return login_form_data, action
