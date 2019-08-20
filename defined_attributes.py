import joblib as jb
import ipaddress
import requests
import regex as re   
from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import urllib.request
from dateutil.parser import parse as date_parse
import datetime
import whois

# Calculates number of months
def diff_month(d1, d2):
    return (d1.year - d2.year) * 12 + d1.month - d2.month


#load the pickle file
#classifier = joblib.load('random_forest_model.pkl')
classifier = jb.load('random_forest_model.pkl')

#input url
print("Enter url:")
url = input()

if not re.match(r"^https?", url):
    url = "http://" + url


try:
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
except:
    response = ""
    soup = -999
# Extracts domain from the given URL
domain = re.findall(r"://([^/]+)/?", url)[0]
# Requests all the information about the domain
whois_response = requests.get("https://www.whois.com/whois/"+domain)

rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
     "name": domain
    })      

# Extracts global rank of the website
try:
    global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
except:
    global_rank = -1      


def url_having_ip(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return -1
    


def url_length(url):
    length=len(url)
    if(length<54):
        return -1
    elif(54<=length<=75):
        return 0
    else:
        return 1


def url_short(url):
    match=re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net',url)
    if match:
        return -1
    else:
        return 1               
def having_at_symbol(url):
    symbol=re.findall(r'@',url)
    if(len(symbol)==0):
        return -1
    else:
        return 1 
    
def doubleSlash(url):
    if re.findall(r"[^https?:]//",url):
        return -1
    else:
        return 1

def prefix_suffix(url):
    subDomain, domain, suffix = extract(url)
    if(domain.count('-')):
        return 1
    else:
        return -1

def sub_domain(url):
    subDomain, domain, suffix = extract(url)
    if(subDomain.count('.')==0):
        return -1
    elif(subDomain.count('.')==1):
        return 0
    else:
        return 1

def SSLfinal_State(url):
    try:
#check wheather contains https       
        if(regex.search('^https',url)):
            usehttps = 1
        else:
            usehttps = 0
#getting the certificate issuer to later compare with trusted issuer 
        #getting host name
        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"):
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0] 
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        
#getting age of certificate
        startingDate = str(certificate['notBefore'])
        endingDate = str(certificate['notAfter'])
        startingYear = int(startingDate.split()[3])
        endingYear = int(endingDate.split()[3])
        Age_of_certificate = endingYear-startingYear
        
#checking final conditions
        if((usehttps==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1) ):
            return -1 #legitimate
        elif((usehttps==1) and (certificate_Auth not in trusted_Auth)):
            return 0 #suspicious
        else:
            return 1 #phishing
        
    except Exception as e:
        
        return 1

def domain_registration(url):
    try:
        w = whois.whois(url)
        updated = w.updated_date
        exp = w.expiration_date
        length = (exp[0]-updated[0]).days
        if(length<=365):
            return 1
        else:
            return -1
    except:
        return 0

def favicon(url):
    #ongoing
    return 1
    '''
    if soup == -999:
        return -1
    else:
        for head in soup.find_all('head'):
            for head.link in soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                if url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                    return 1
                else:
                    return -1
     '''                   
def port(url):
    try:
        port = domain.split(":")[1]
        if port:
            return 1
        else:
            return -1
    except:
        return -1

def https_token(url):
    subDomain, domain, suffix = extract(url)
    host =subDomain +'.' + domain + '.' + suffix 
    if(host.count('https')): #attacker can trick by putting https in domain part
        return 1
    else:
        return -1

def request_url(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        imgs = soup.findAll('img', src=True)
        total = len(imgs)
        linked_to_same = 0
        avg =0
        for image in imgs:
            subDomain, domain, suffix = extract(image['src'])
            imageDomain = domain
            if(websiteDomain==imageDomain or imageDomain==''):
                linked_to_same = linked_to_same + 1
        vids = soup.findAll('video', src=True)
        total = total + len(vids)
        
        for video in vids:
            subDomain, domain, suffix = extract(video['src'])
            vidDomain = domain
            if(websiteDomain==vidDomain or vidDomain==''):
                linked_to_same = linked_to_same + 1
                linked_outside = total-linked_to_same
        if(total!=0):
            avg = linked_outside/total
        if(avg<0.22):
            return -1
        elif(0.22<=avg<=0.61):
            return 0
        else:
            return 1
    except:
        return 0


def url_of_anchor(url):
    try:
        subDomain, domain, suffix = extract(url)
        websiteDomain = domain
        
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        anchors = soup.findAll('a', href=True)
        total = len(anchors)
        linked_to_same = 0
        avg = 0
        for anchor in anchors:
            subDomain, domain, suffix = extract(anchor['href'])
            anchorDomain = domain
            if(websiteDomain==anchorDomain or anchorDomain==''):
                linked_to_same = linked_to_same + 1
        linked_outside = total-linked_to_same
        if(total!=0):
            avg = linked_outside/total
            
        if(avg<0.31):
            return -1
        elif(0.31<=avg<=0.67):
            return 0
        else:
            return 1
    except:
        return 0
    
def Links_in_tags(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        
        no_of_meta =0
        no_of_link =0
        no_of_script =0
        anchors=0
        avg =0
        for meta in soup.find_all('meta'):
            no_of_meta = no_of_meta+1
        for link in soup.find_all('link'):
            no_of_link = no_of_link +1
        for script in soup.find_all('script'):
            no_of_script = no_of_script+1
        for anchor in soup.find_all('a'):
            anchors = anchors+1
        total = no_of_meta + no_of_link + no_of_script+anchors
        tags = no_of_meta + no_of_link + no_of_script
        if(total!=0):
            avg = tags/total

        if(avg<0.25):
            return -1
        elif(0.25<=avg<=0.81):
            return 0
        else:
            return 1        
    except:        
        return 0

def sfh(url): 
    ''''
    try:
        for form in soup.find_all('form', action= True):
           if form['action'] =="" or form['action'] == "about:blank" :
              return -1
              break
           elif url not in form['action'] and domain not in form['action']:
               return 0
               break
           else:
               return 1
               break
    except:
        '''
    return 0
           
def email_submit(url):
    try:
        opener = urllib.request.urlopen(url).read()
        soup = BeautifulSoup(opener, 'lxml')
        if(soup.find('mailto:')):
            return 1
        else:
            return -1 
    except:
        return 0

    return 0
def abnormal_url(url):
    try:
        if response.text == "":
            return 1
        else:
            return -1
    except:
        return 0

def redirect(url):
    try: 
        if len(response.history) <= 1:
            return -1
        elif len(response.history) <= 4:
            return 0
        else:
            return 1
    except:
        return 0

def on_mouseover(url):
    try:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return -1
    except:
        return 0

def rightClick(url):
    try:
        if re.findall(r"event.button ?== ?2", response.text):
            return 1
        else:
            return -1
    except:
        return 0

def popup(url):
    try:
        if re.findall(r"alert\(", response.text):
            return 1
        else:
            return -1
    except:
        return 0
def iframe(url):
    try:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 1
        else:
            return -1
    except:
        return 0

def age_of_domain(url):
    try:
        if response == "":
            data_set.append(-1)
        else:
            try:
                registration_date = re.findall(r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
                if diff_month(date.today(), date_parse(registration_date)) >= 6:
                    return -1
                else:
                    return 1
            except:
                    return 1
    except:
        return 0        
def dns(url):
    dns = 1
    try:
        registration_date = re.findall(r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
        d = whois.whois(domain)
    except:
        dns=-1
    if dns == -1:
        return -1
    else:
        if registration_length / 365 <= 1:
            return -1
        else:
            return 1

def web_traffic(url):
    try:
        if global_rank > 0 and global_rank < 100000:
            return -1
        else:
            return 1
    except:
        return 1

def page_rank(url):
    try:
        if global_rank > 0 and global_rank < 100000:
            return -1
        else:
            return 1
    except:
        return 1

def google_index(url):
    try:
        if global_rank > 0 and global_rank < 100000:
            return -1
        else:
            return 1
    except:
        return 1

def links_pointing(url):
    number_of_links = len(re.findall(r"<a href=", response.text))
    if number_of_links == 0:
        return 1
    elif number_of_links <= 2:
        return 0
    else:
        return -1

def statistical(url):
   url_match=re.search('at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',url)
   ip_address=socket.gethostbyname(domain)
   ip_match=re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                           '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                           '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                           '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                           '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                           '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',ip_address)
   if url_match:
        return -1
   elif ip_match:
        return -1
   else:
        return 1
def main(url):
    check = [[url_having_ip(url),url_length(url),url_short(url),having_at_symbol(url),
             doubleSlash(url),prefix_suffix(url),sub_domain(url),SSLfinal_State(url),
              domain_registration(url),favicon(url),port(url),https_token(url),request_url(url),
              url_of_anchor(url),Links_in_tags(url),sfh(url),email_submit(url),abnormal_url(url),
              redirect(url),on_mouseover(url),rightClick(url),popup(url),iframe(url),
              age_of_domain(url),dns(url),web_traffic(url),page_rank(url),google_index(url),
              links_pointing(url),statistical(url)]]
    
    
    print(check)
    return check
    print(imgs)

#checking and predicting
checkprediction=main(url)
prediction = classifier.predict(checkprediction)
print(prediction)
if prediction==1:
    print('legitimate website')
elif prediction==-1:
    print('Phishing website')
else:
    print('No Data Found')
 
