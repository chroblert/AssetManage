from django import template
from django.template.defaultfilters import stringfilter
import base64

register = template.Library()
@stringfilter
def base64_jc(value,arg):
    if arg == "encode":
        return str(base64.urlsafe_b64encode(value.encode('utf-8')),encoding="utf-8")
    elif arg == "decode":
        return base64.urlsafe_b64decode(value).decode("utf-8")
    return "请输入正确参数"

def checkResDisplay(value):
    if value == "True" or value == "true":
        return "通过"
    else:
        return "未通过"
def setclass(value):
    if value != "True" and value != "true":
        classstr='class=jc-red-badge'
        return classstr
register.filter('base64',base64_jc)
register.filter('checkres',checkResDisplay)
register.filter('setclass',setclass)