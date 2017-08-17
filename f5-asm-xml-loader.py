#! /usr/bin/python
import os
import sys
import bigsuds
import argparse
import getpass
import datetime
import time
import base64


#########################################################
#	DEFAULTS											#
#########################################################
DEFAULT_F5PORT			= '443'
XML_CATALOGUE_DUMP		= './xml.catalogue.dump'
XML_ASM_DUMP			= './xml.asm.dump'
XML_DICTIONARY_ASMNAME	= 'ASM Policy Name'
XML_DICTIONARY_ASMFILE	= 'ASM Policy File'
XML_DICTIONARY_ACTIVE	= 'ASM Policy Active'



def asm_xml_file_download(bigip_obj,src_file,dst_file,chunk_size,buff = 1048576):
	'''
	file_download - Download file from F5 via iControl
	Usage - file_download(bigip_obj,src_file,dst_file,chunk_size,buff = n)
	@param bigip_obj: the bigsuds icontol object
	@param src_file: file on F5
	@param dst_file: local file
	@param chunk_size: download size for each chunk
	@param buff: (optional) size of file write buffer, default 1MB
	Returns - returns file size in bytes if job completed
	Raises exceptions if job failed
	'''
	# Set begining vars
	foffset = 0
	timeout_error = 0
	fbytes = 0
     
	# Open temp file for writing, default buffer size is 1MB
	f_dst = open(dst_file + '.tmp','wb',buff)
	
	# Main loop
	while True:
		# Try to download chunk
		try:
			chunk = bigip_obj.ASM.Policy.download_policy(policy_name = src_file,chunk_size = chunk_size,file_offset = foffset)
		except:
			timeout_error += 1
			# is this the 3rd connection attempt?
			if (timeout_error >= 3):
				# Close tmp file & delete, raise error
				f_dst.close()
				os.remove(dst_file + '.tmp')
				raise
			else:
				# Otherwise wait 2 seconds before retry
				time.sleep(2)
				continue
		
		# reset error counter after a good connect
		timeout_error = 0
		
		# Write contents to file
		fchunk = base64.b64decode(chunk['return']['file_data'])
		f_dst.write(fchunk)
		fbytes += sys.getsizeof(fchunk) - 40
		
		# Check to see if chunk is end of file
		fprogress = chunk['return']['chain_type']
		if (fprogress == 'FILE_FIRST_AND_LAST')  or (fprogress == 'FILE_LAST' ):
			# Close file, rename from name.tmp to name
			f_dst.close()
			os.rename(dst_file + '.tmp' , dst_file)
			return fbytes

		# set new file offset
		foffset = chunk['file_offset']


def asm_xml_file_upload(bigip_obj, dest_file_name, local_file):
    fileobj = open(local_file,'r')
    
    DF_CHUNK_SIZE = 1024*10
    done = False
    first = True
    timeout_error = 0
	
    while not done:
		text = base64.b64encode(fileobj.read(DF_CHUNK_SIZE))
		
		if first:
			if len(text) < DF_CHUNK_SIZE:
				chain_type = 'FILE_FIRST_AND_LAST'
			else:
				chain_type = 'FILE_FIRST'
			first = False
			
		else:
			if len(text) < DF_CHUNK_SIZE:
				chain_type = 'FILE_LAST'
				done = True
			else:
				chain_type = 'FILE_MIDDLE'
				
		try:
			bigip_obj.ASM.Policy.upload_policy(dest_file_name,file_context=dict(file_data=text,chain_type=chain_type))
		except:
			timeout_error += 1
			# is this the 3rd connection attempt?
			if (timeout_error >= 3):
				# Close tmp file & delete, raise error
				fileobj.close()
				print "(-) Error: Timeout error reached!"
				raise
			else:
				# Otherwise wait 2 seconds before retry
				time.sleep(2)
				continue


# MAIN ---------------------------------#
def main():
	# PARSER DEFINITION
	parser=argparse.ArgumentParser(description="F5 ASM XML Policy loader tool for BIG-IP (iControl SOAP)")
	parser.add_argument("--host", nargs=1, default=['none'], help="F5 host to connect to",required=True)
	parser.add_argument("--port", nargs=1, default=[DEFAULT_F5PORT], help="HTTPS port (defaults to "+DEFAULT_F5PORT+")")
	parser.add_argument("--username", nargs=1, default=[''], help="Username", required=True)
	parser.add_argument("--password", nargs=1, default=[''], help="Password")
	parser.add_argument("--download", action="store_true", help="Download ASM XML Policies and generate catalogue")
	parser.add_argument("--upload", nargs=1, default=[''], help="Upload ASM XML Policies using catalogue")
	parser.add_argument("--activate", action="store_true", help="Activate ASM XML Policies on upload (11.4.0 and later)")
	parser.add_argument("--deactivate", action="store_true", help="Deactivate ASM XML Policies on upload (11.4.0 and later)")
	args = parser.parse_args()


	# Input parameters
	host				= args.host[0]
	port				= args.port[0]
	username			= args.username[0]
	password			= args.password[0]
	download			= args.download
	upload				= args.upload[0]
	activate			= args.activate
	deactivate			= args.deactivate
	
	# Verify input
	if ((download is False) and (upload == "") or (download is True) and not (upload == "")):
		print "(-) Error: You must chose either an upload or download operation!"
		exit (-1)
	
	# Verify that activate and deactivate are not active simultaneously
	if activate is True and deactivate is True:
		print "(-) Error: You cannot simultaneously specify the 'activate' and 'deactivate' flags!"
		exit (-1)
		

	# If password is not passed as argument, ask for it:
	if password == '':
		password		= getpass.getpass()

	
	# Generate timestamp to record operation
	timestamp = str(datetime.datetime.now()).replace(" ","_").replace(":","_").split(".")[0]
	catalogueFileName		= XML_CATALOGUE_DUMP+"/"+timestamp+"_catalogue_host_"+host+".csv"
	catalogueFolderASM		= XML_ASM_DUMP+"/"+timestamp+"_host_"+host
	tmosVersion				= 0
	
	try:
		# BIG-IP Connector configuration
		bigIPConnector = bigsuds.BIGIP(host, username, password, int(port),timeout=1,verify=False)
		
		# Reconnect with longer timeout if first auth was ok (5 minute timeout)
		bigIPConnector = bigsuds.BIGIP(host, username, password, int(port),timeout=300,verify=False)
		
		# Retrieve version (if older than TMOS 11.4.0, ASM Activation not possible)
		tmosVersionS = bigIPConnector.System.SystemInfo.get_version()
		tmosVersionS = tmosVersionS.replace("BIG-IP_v","")
		if len(tmosVersionS.split(".")) < 3:
			tmosVersionS = tmosVersionS+".0"
		tmosVersion = int(tmosVersionS.replace(".",""))
		
		
	except:
		print "(-) Error: Could not connect to BIG-IP. Program is now exiting!"
		exit (-1)
	
	
	# Check if base storage folders exist. If not, create them.
	for baseFolder in [XML_CATALOGUE_DUMP, XML_ASM_DUMP]:
		if not os.path.isdir(baseFolder):
			os.makedirs(baseFolder)
	
	
	# Now we need to tidy everything in a dictionary
	# Friendly name | ASM Policy File | Active Flag
	xmlCatalogueContent = {}
	
		
	# Process a download operation
	if download is True:
		print "(+) Info: Downloading complete ASM XML Policies catalogue to local host..."
		# Check if catalogue storage folders exist. If not, create them.
		for catalogueFolder in [catalogueFolderASM]:
			if not os.path.isdir(catalogueFolder):
				os.makedirs(catalogueFolder)
		
		
		# Get the ASM Policies names to extract IDs
		asmList = bigIPConnector.ASM.Policy.get_list()
		asmVS = bigIPConnector.ASM.
		
		
		# Iterate the asm list -------------------------------------------- #
		for asm in asmList:
			print "(+) Info: Exporting XML for policy '"+asm+"'"
			try:
				bigIPConnector.ASM.Policy.export_policy_xml(asm,'/var/tmp/'+asm.replace("/","_")+'.xml')
				asm_xml_file_download(bigIPConnector,asm.replace("/","_")+'.xml',catalogueFolderASM+"/"+asm.replace("/","_")+".xml",65535)
				
										
				# If TMOS greater or equal to 11.4.0 check active flag. If not, mark as inactive
				if tmosVersion >= 1140:
					if activate is True:
						activeFlag = 'True'
						
					elif deactivate is True:
						activeFlag = 'False'
						
					else:
						activeFlag = bigIPConnector.ASM.Policy.get_active([asm])[0]
						
				else:
					activeFlag = 'False'
				
				if asm not in xmlCatalogueContent:
					xmlCatalogueContent[asm] = {}
					xmlCatalogueContent[asm][XML_DICTIONARY_ASMFILE] = catalogueFolderASM+"/"+asm.replace("/","_")+".xml"
					xmlCatalogueContent[asm][XML_DICTIONARY_ACTIVE] = activeFlag
			
				
			except Exception, e:
				print "(-) Error: Exporting XML for policy '"+asm+"' failed"
				#print e
				
		# ----------------------------------------------------------------- #
		
		
		
		# Process the ASM XML Catalogue ----------------------------------- #
		with open(catalogueFileName, "w") as catalogueFile:
			
			# Write the catalogue header
			catalogueFile.write("\""+XML_DICTIONARY_ASMNAME+"\""\
				+",\""+XML_DICTIONARY_ASMFILE+"\""\
				+",\""+XML_DICTIONARY_ACTIVE+"\""\
				+"\n")
			
			# Let's write the catalogue content, line per line
			for asmPolicy in xmlCatalogueContent:
				catalogueFile.write("\""+asmPolicy+"\""\
				+",\""+xmlCatalogueContent[asmPolicy][XML_DICTIONARY_ASMFILE]+"\""\
				+",\""+str(xmlCatalogueContent[asmPolicy][XML_DICTIONARY_ACTIVE])+"\""\
				+"\n")
		# ----------------------------------------------------------------- #
		
		
		
	# Process an upload operation
	elif not (upload == ""):
		if not os.path.isfile(upload):
			print "(-) Error: You must chose a valid file to upload!"
			exit (-1)
		
		# Get the ASM Policies names to extract IDs
		asmList = bigIPConnector.ASM.Policy.get_list()
		
		print "(+) Info: Uploading complete ASM Policy catalogue to remote host..."
		# Parse the catalogue file to know what to upload
		with open(upload, "r") as catalogueFile:
			
			# Ignore the header file
			header = 0
			
			# Iterate line by line
			for line in catalogueFile:
				
				# Skip the header
				if header == 0:
					header = 1
				
				# Process the content
				else:
					lineComponents = line.replace("\"","").split(",")
					if len(lineComponents) == 3:
											
						# Retrieve the components
						asm				= lineComponents[0].strip()
						asmPolicyFile	= lineComponents[1].strip()
						asmActive		= lineComponents[2].strip()
						
						print "(+) Info: Importing XML for policy '"+asm+"'"
						
						# Upload the ASM Policy - if present
						if not asm == '':
							if not os.path.isfile(asmPolicyFile):
								print "(-) Warning: Ignoring ASM Policy '"+asm+"' because file path is not valid"
							else:
								try:
									
									# If policy already exists in target machine, delete it.
									# Warning:  Deleting the existing policy will also remove the policy from the associated virtual server if there is one.
									# It will also permanently delete all of the request log entries generated by this security policy.
									# The iControl REST gives an option to replace without deleting
									if asm in asmList:
										bigIPConnector.ASM.Policy.set_active([asm],["0"])
										bigIPConnector.ASM.Policy.delete_policy([asm])
									
									# Upload the policy to the BIG-IP
									asm_xml_file_upload(bigIPConnector, asm.replace("/","_")+'.xml', asmPolicyFile)

									# Import the policy
									remoteAsmPolicyFile = '/var/tmp/'+asm.replace("/","_")+'.xml'
									# webapp_name is only used in pre-11.4.0, starting with 11.4.0 it uses Traffic Policies
									bigIPConnector.ASM.Policy.import_policy(webapp_name=asm, filename=remoteAsmPolicyFile)
									
									# mark policy as active (if greater or equal to 11.4.0, depending on ARGS or CATALOGUE flag)
									if tmosVersion >= 1140:
										if deactivate is False:
											if activate is True or asmActive == "True":
												bigIPConnector.ASM.Policy.set_active([asm],["1"])
												bigIPConnector.ASM.Policy.apply_policy([asm])											
											
																		
								except Exception, e:
									print "(-) Warning: Could not upload ASM Policy '"+asm+"'"
									#print e
					
					else:
						print "(-) Warning: Ignoring mal-formed catalogue line: '"+line+"'" 
	
	print "(+) Success!"
	return
# ENDOF MAIN ---------------------------#


if __name__ == '__main__':
	main()
	exit(0)
