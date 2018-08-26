from apiclient import discovery
from apiclient import errors
from httplib2 import Http
from oauth2client import file, client, tools
import base64
import time
import dateutil.parser as parser
from datetime import datetime, timedelta, timezone
import datetime
import csv
import io
import PyPDF2
from erp_connect import newcandidate
import re
import unidecode


def personal_info(cv, print_info=False):

    mails = re.findall(r'[\w\.-]+@[\w\.-]+', cv)
    if print_info:
        print("Mails:")
        for j in mails:
            print(j)
        print("Postal Code:")


    cp = re.finditer(r"\W\d{5}\W", cv)
    codis = []
    adress = []
    for j in cp:
        index1 = cv[0:j.span()[0]].rfind('\n')
        if index1 == -1:
            index1 = 0
        index2 = cv[j.span()[1]:-1].find('\n')
        adress = adress + [cv[index1 + 2:j.span()[1] + index2]]
        codis = codis + [j[0]]
        if print_info:
            print(j[0])
            print(cv[index1 + 2:j.span()[1] + index2])


    phones = re.findall(r"[\d{1,2}]?[-.\s]?\d{3}[-.\s]?\d{3}[-.\s]?\d{3}", cv)
    phonesillos = re.findall(r"[\d{1,2}]?[-.\s]?\d{3}[-.\s]?\d{2}[-.\s]?\d{2}[-.\s]?\d{2}", cv)
    for x in phonesillos:
        if x not in phones:
            phones.extend(x)
    if print_info:
        print("Phones:")
        for j in phones:
            print(j)

    return mails, codis, adress, phones



#inici del codi que entra en el correu
def handler(event, context):

    #la funcio get attachements retorna un llista amb un boolea de si tenim o no un curriculum i una string amb el curriculum
    def GetAttachments(service, user_id, msg_id, store_dir="C:/Users/joanarino/Documents/bot a join/bla.pdf"):
    	found_pdf = False
    	lletra = ""
    	try:
    		message = service.users().messages().get(userId=user_id, id=msg_id).execute()
    		parts = [message['payload']]
    		while parts:
    			part = parts.pop()
    			if part.get('parts'):
    				parts.extend(part['parts'])
    			if part.get('filename'):
    				if 'data' in part['body']:
    					file_data = base64.urlsafe_b64decode(part['body']['data'].encode('UTF-8'))
    					#self.stdout.write('FileData for %s, %s found! size: %s' % (message['id'], part['filename'], part['size']))
    				elif 'attachmentId' in part['body']:
    					attachment = service.users().messages().attachments().get(
    						userId=user_id, messageId=message['id'], id=part['body']['attachmentId']
    					).execute()
    					file_data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
    					#self.stdout.write('FileData for %s, %s found! size: %s' % (message['id'], part['filename'], attachment['size']))
    				else:
    					file_data = None
    				if file_data:
                        #ens assegurem que el fitxer tingui .pdf en el nom i no dni
    					if ".pdf" in part['filename']:
    						if "dni" not in part['filename'].lower():
    							found_pdf = True
                                #si es aixi n'extraiem el text usant el package pypdf2
    							try:
    								pdf_content = io.BytesIO(file_data)
    								pdfReader = PyPDF2.PdfFileReader(pdf_content)
    								for i in range (0, pdfReader.numPages):
    									pageObj = pdfReader.getPage(i)
    									lletra = lletra + pageObj.extractText()
    							except:
    								pass
    	except errors.HttpError as error:
    		print ("An error occurred: %s' % error")
    	return [found_pdf, lletra]


    #usa les credencials per obrir el gmail
    SCOPES = 'https://www.googleapis.com/auth/gmail.readonly' # we are using modify and not readonly, as we will be marking the messages Read
    store = file.Storage('storage.json')
    creds = store.get()
    clos= '''if not creds or creds.invalid:
    	flow = client.flow_from_clientsecrets('credentials.json', SCOPES)
    	creds = tools.run_flow(flow, store)'''
    GMAIL = discovery.build('gmail', 'v1', http=creds.authorize(Http()))
    user_id =  'me'
    label_id_one = 'INBOX'
    label_id_two = 'UNREAD'

    unread_msgs = GMAIL.users().messages().list(userId='me').execute()#podriem afegiri mes parametres per nomes escollir alguns correus
    # diccionari. la key es 'messages'
    mssg_list=[]
    if(unread_msgs['resultSizeEstimate']!=0): mssg_list = unread_msgs['messages']

    print ("Total unread messages in inbox: ", str(len(mssg_list)))

    final_list = [ ]

    for mssg in mssg_list:
    	temp_dict = { }
    	m_id = mssg['id'] 
    	message = GMAIL.users().messages().get(userId=user_id, id=m_id).execute() 
    	temp_dict['Snippet'] = message['snippet'] 
    	payld = message['payload'] 
    	headr = payld['headers'] 
    	for each in headr: 
    		if each['name'] == 'Subject':
    			msg_subject = each['value']
    			temp_dict['Subject'] = msg_subject
    		elif each['name'] == 'Date':
    			msg_date = each['value']
    			date_parse = (parser.parse(msg_date))
    			temp_dict['Date'] = date_parse
    			#m_date = (date_parse.date())
    			#temp_dict['Date'] = str(m_date)
    		elif each['name'] == 'From':
    			msg_from = each['value']
    			temp_dict['Sender'] = msg_from
    		elif each['name'] == 'To':
    			msg_to = each['value']
    			temp_dict['Tor'] = msg_to
    		else:
    			pass
        #escollim nomes aquells correus enviats les ultimes 3 hores amb insights com a destinatari i amb unattachement .pdf
    	if not temp_dict.get('Date'):
    		continue
    	if(temp_dict['Date'] < (datetime.datetime.now(timezone.utc) - timedelta(hours=3))):
    		continue
    	temp_dict['Date']
    	if not temp_dict.get('Tor'):
    		continue
    	attache = GetAttachments(GMAIL, "me", m_id)
    	if not (attache[0]):
    		continue
    	temp_dict['Attachment'] = attache[1]
    	try:
    		mssg_parts = payld['parts'] # fetching the message parts
    		part_one  = mssg_parts[0] # fetching first element of the part
    		part_body = part_one['body'] # fetching body of the message
    		if(part_body['size']>0):
    			part_data = part_body['data'] # fetching data from the body
    			clean_one = part_data.replace("-","+") # decoding from Base64 to UTF-8
    			clean_one = clean_one.replace("_","/") # decoding from Base64 to UTF-8
    			clean_two = base64.b64decode (bytes(clean_one, 'UTF-8')) # decoding from Base64 to UTF-8
    			clean_three = clean_two.decode("UTF-8")
    			temp_dict['Message_body'] = clean_three
    		else:
    			temp_dict['Message_body'] = ""
    	except:
    		pass

