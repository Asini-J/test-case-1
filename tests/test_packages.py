import requests.init as init


def test_can_access_urllib3_attribute():
    init.packages.urllib3


def test_can_access_idna_attribute():
    init.packages.idna


def test_can_access_chardet_attribute():
    init.packages.chardet
