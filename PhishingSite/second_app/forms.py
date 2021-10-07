#for home.html
from django import forms
class UrlForm(forms.Form):
    your_url = forms.CharField(label='Your url', max_length=100)
