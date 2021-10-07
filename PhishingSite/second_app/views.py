from django.http import HttpResponse
from django.shortcuts import render
import pickle
import os
from first_app import settings
from .FeatureExtraction import *
def home(request):
    return render(request, "home.html", {})
#for result.html
def generate_url_dataframe(url_val):
	protocol = []
	domain = []
	path = []
	having_ip = []
	len_url = []
	having_at_symbol = []
	redirection_symbol = []
	prefix_suffix_separation = []
	sub_domains = []
	tiny_url = []
	web_traffic = []
	domain_registration_length = []
	dns_record = []
	statistical_report = []
	age_domain = []
	http_tokens = []
	fe_obj = FeatureExtraction()
	protocol.append(fe_obj.getProtocol(url_val))
	domain.append(fe_obj.getDomain(url_val))
	path.append(fe_obj.getPath(url_val))
	having_ip.append(fe_obj.havingIP(url_val))
	len_url.append(fe_obj.long_url(url_val))
	having_at_symbol.append(fe_obj.have_at_symbol(url_val))
	redirection_symbol.append(fe_obj.redirection(url_val))
	prefix_suffix_separation.append(fe_obj.prefix_suffix_separation(url_val))
	sub_domains.append(fe_obj.sub_domains(url_val))
	tiny_url.append(fe_obj.sub_domains(url_val))
	web_traffic.append(fe_obj.web_traffic(url_val))
	domain_registration_length.append(fe_obj.domain_registration_length(url_val))
	dns_record.append(fe_obj.dns_record(url_val))
	statistical_report.append(fe_obj.statistical_report(url_val))
	age_domain.append(fe_obj.age_domain(url_val))
	http_tokens.append(fe_obj.https_token(url_val))
	d={'Protocol':pd.Series(protocol),'Domain':pd.Series(domain),'Path':pd.Series(path),'Having_IP':pd.Series(having_ip),
	'URL_Length':pd.Series(len_url),'Having_@_symbol':pd.Series(having_at_symbol),
	'Redirection_//_symbol':pd.Series(redirection_symbol),'Prefix_suffix_separation':pd.Series(prefix_suffix_separation),
	'Sub_domains':pd.Series(sub_domains),'tiny_url':pd.Series(tiny_url),'web_traffic' : pd.Series(web_traffic) ,
	'domain_registration_length':pd.Series(domain_registration_length),'dns_record':pd.Series(dns_record),
	'statistical_report':pd.Series(statistical_report),'age_domain':pd.Series(age_domain),'http_tokens':pd.Series(http_tokens)}
	data=pd.DataFrame(d)
	data = data.dropna()
	data = data.drop(data.columns[[0,1,2]],axis=1)
	return data


def result(request):
	#print (os.path.join(settings.BASE_DIR,"\\Phishing\\PhishingSite\\second_app\\model\\custom_rf_classifiers.sav"))
	val = pickle.load(open(os.path.join(settings.BASE_DIR,"\\Phishing\\PhishingSite\\second_app\\model\\custom_svm_classifiers_poly.sav"),'rb'))
	lis = []
	ans = {}
	lis.append(request.GET['your_url'])
	#ans = val.predict(generate_url_dataframe(ans['url']))
	ans['url'] = request.GET['your_url']
	guess = val.predict(generate_url_dataframe(ans['url']))[0]
	if guess == 0:
		ans['prediction'] = "Genuine Link"
	else:
		ans['prediction'] = "A Phishing Link"
	print (ans['prediction'])
	return render(request, "result.html", ans)
