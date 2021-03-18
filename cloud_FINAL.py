from basic_defs import cloud_storage, NAS

import os
import sys

import boto3
import base64
import hashlib 
from azure.storage.blob import BlobServiceClient
from google.cloud import storage

class AWS_S3(cloud_storage):
    def __init__(self):
        # TODO: Fill in the AWS access key ID
        self.access_key_id = ""
        # TODO: Fill in the AWS access secret key
        self.access_secret_key = ""
        # TODO: Fill in the bucket name
        self.bucket_name = "csce678-s21-p1-"
         # Load client using access id and secret key
        self.client = boto3.client('s3', aws_access_key_id=self.access_key_id, aws_secret_access_key=self.access_secret_key)

    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from boto3
    #     boto3.session.Session:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html
    #     boto3.resources:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html
    #     boto3.s3.Bucket:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#bucket
    #     boto3.s3.Object:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#object
        
        
    def read_block(self, offset):
        # Get object and read from the Streaming Body
        # In AWS S3 blocks are stored as single objects
        response = self.client.get_object(Bucket=self.bucket_name, Key=str(offset))
        return bytearray(base64.b64decode(response['Body'].read()))
        
        
    def list_blocks(self):
    	# Get object in terms dict
    	response = self.client.list_objects_v2(Bucket=self.bucket_name)
    	offset_arr = []
    	if 'Contents' in response:
        	for i in response['Contents']:
        		offset_arr.append(int(i['Key']))
        		#offset_arr.append(i['Key'])
		return offset_arr 
		
    def write_block(self, block, offset):
        # Store as base64 strings
        self.client.put_object(Body=base64.b64encode(block), Bucket=self.bucket_name, Key=str(offset))
        
    def delete_block(self, offset):
        # Delete the object using the given offset
        self.client.delete_object(Bucket=self.bucket_name, Key=str(offset))
    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from boto3
    #     boto3.session.Session:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html
    #     boto3.resources:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html
    #     boto3.s3.Bucket:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#bucket
    #     boto3.s3.Object:
    #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#object


class Azure_Blob_Storage(cloud_storage):
    def __init__(self):
        # TODO: Fill in the Azure key
        self.key = ""
        # TODO: Fill in the Azure connection string
        self.conn_str = ""
        # TODO: Fill in the account name
        self.account_name = "csce678s21"
        # TODO: Fill in the container name
        self.container_name = "csce678-s21-p1-"
        # Load client using connection string
        self.client = BlobServiceClient.from_connection_string(conn_str=self.conn_str)
        # Load client's container that contains blob
        self.container = self.client.get_container_client(container=self.container_name)
        
    def read_block(self, offset):
        # Get the blob from the specified container and read from the blob
        response = self.client.get_blob_client(container=self.container_name, blob=str(offset))
        # To read we can use content_as_bytes, or content_as_text, readall
        return bytearray(base64.b64decode(response.download_blob().content_as_bytes()))
        
    def write_block(self, block, offset):
        # Store as base64 strings
        self.client.get_blob_client(container=self.container_name, blob=str(offset)).upload_blob(data=base64.b64encode(block), overwrite=True)
    
    def list_blocks(self):
    	# Get blob in terms of iterator, if it is empty return empty array
    	response = self.container.list_blobs()
    	offset_arr = []
    	for i in response:
            offset_arr.append(int(i.name))
        return offset_arr    
    
    def delete_block(self, offset):
        # Delete the blob using the given offset
        self.client.get_blob_client(container=self.container_name, blob=str(offset)).delete_blob()
        
    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from azure.storage.blob
    #    blob.BlobServiceClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python
    #    blob.ContainerClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python
    #    blob.BlobClient:
    #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobclient?view=azure-python

class Google_Cloud_Storage(cloud_storage):
    def __init__(self):
        # Google Cloud Storage is authenticated with a **Service Account**
        # TODO: Download and place the Credential JSON file
        self.credential_file = "gcp-credential.json"
        # TODO: Fill in the container name
        self.bucket_name = "csce678-s21-p1-"
        # Load client using the JSON file
        self.client = storage.Client.from_service_account_json(self.credential_file)
        # Load client's bucket that contains blob
        self.bucket = self.client.bucket(self.bucket_name)
        
    def read_block(self, offset):
        # Get the blob from the specified bucket and read from the blob
        # Download the blob as string and return bytearray
        response = self.bucket.blob(str(offset)).download_as_string()
        return bytearray(base64.b64decode(response))
        
    def write_block(self, block, offset):
        # Store as base64 strings
        self.bucket.blob(str(offset)).upload_from_string(base64.b64encode(block))
    
    def list_blocks(self):
    	# Get blob in terms of iterator, if it is empty return empty array
    	response = self.bucket.list_blobs()
    	offset_arr = []
    	for i in response:
            offset_arr.append(int(i.name))
        return offset_arr    
    
    def delete_block(self, offset):
        # Delete the blob using the given offset
        self.bucket.blob(str(offset)).delete()

    # Implement the abstract functions from cloud_storage
    # Hints: Use the following APIs from google.cloud.storage
    #    storage.client.Client:
    #        https://googleapis.dev/python/storage/latest/client.html
    #    storage.bucket.Bucket:
    #        https://googleapis.dev/python/storage/latest/buckets.html
    #    storage.blob.Blob:
    #        https://googleapis.dev/python/storage/latest/blobs.html

class RAID_on_Cloud(NAS):
    def __init__(self):
        self.backends = [
                AWS_S3(),
                Azure_Blob_Storage(),
                Google_Cloud_Storage()
            ]
        self.fds = dict()    
   
    
    # def open(self, filename):
    #     #Create a file descriptor to represent the file. 
    #     #Because RAID-on-Cloud NAS does not store metadata in the cloud, 
    #     #open(filename) does not distinguish whether the file has been previously
    #     #created and written. open(filename) should always succeed and return a file 
    #     #descriptor. All files are opened as readable and writable
  
    def open(self, filename):
        newfd = None
        for fd in range(256):
            if fd not in self.fds:
                newfd = fd
                break
        if newfd is None:
            raise IOError("Opened files exceed system limitation.")
        self.fds[newfd] = filename
        return newfd
        
        
    def get_cloud_from_hash_map(self,key):
        hash_value = hash(key)
        mod_val = hash_value%3
        cloud_picked = [x for i,x in enumerate(self.backends) if i!=mod_val]
        #m= hashlib.sha()
        #m=update(bytearray(key))
        block = hashlib.sha256(key).hexdigest()
        block_offset = int(block,16)
    
        # print("Block Offset",block_offset)
        # print("Type of Block Offset",type(block_offset))
        return cloud_picked, block_offset
    
    def read(self, fd, length, offset):
        
        #Read the data of the opened file descriptor, as the given length and offset, 
        #and return a byte array that contains the data. If the file does not exist in the cloud,
        #or the offset has exceeded the end of the file, return a byte array with 0 byte.

        #step1: get file from fd
        #step2: do the alignment
        #step3: hash function(filename, alignmentoffset) = hexadecimal 
        		#e.g hash_val = int(hashlib.md5(filename+align_offset).hexdigest())

        #step4: read from cloud storages
        		#if hash_valmod3 = 0:
        			#aws.read_block(hash_val) or azure.read_block(hash_val)
        		#if hash_valmod3 = 1:
        			#aws.read_block(hash) or google.read_block()
        		#if hash_valmod3 = 2: 
        			#google.read_block() or azure.read_block()
        			
        #step 1: get file from fd
        
        output = bytearray()
        
        
        if fd not in self.fds:
            return output
        else:
            filename = self.fds[fd]
            #step 2: do the alignment
            align_offset =  int(offset/4096) 
            end_block = int(((offset+length)/4096))
            number_blocks = end_block - align_offset + 1 
            #number_blocks =  1 
                
        #   #step 3: hash function
        #     hash_val =  int(hashlib.md5(filename+align_offset).hexdigest())
           
        #   #step 4: read from cloud storage
        #     if hash_val%3 == 0:
        #         self.backends[0]AWS_S3.read_block(hash_val) 
            		
        #     if hash_val%3 == 1:
        #         Google_Cloud_Storage.read_block(hash_val)
            		
        #     if hash_val%3 = 2: 
        #         Google_Cloud_Storage.read_block(hash_val) or Azure_Blob_Storage.read_block(hash_val)
    
            #returns clouds picked and block offset
            # print("BLOCK_OFF", block_offset)
            
            #return a byte array that contains the data upto the given length (use len)
            for i in range(number_blocks):
                #print("Block number",i)
                #block = cloud_picked.read_block(hex(int(block_offset,16)+i*4096)) #returns block as a byte array based on the given key (block_offset) 
                cloud_picked, block_offset = self.get_cloud_from_hash_map(str(filename)+str(align_offset+i))
                
                if block_offset not in cloud_picked[0].list_blocks():
                    break
                else:
                    block = cloud_picked[0].read_block(block_offset)
                
                if i==0: #first block
                    if (offset%4096) + length < 4096:
                        output = block[(offset%4096):(offset%4096)+length] #e.g skip first 4 bytes from the first block if the offset is 5000 (e.g hello.txt, 5000)
                    else:
                        output = block[(offset%4096):4096] #
                #need to figure out how to trim data from the ending block
                elif i==number_blocks-1: #for last block trimming
                    if ((offset+length)%4096) == 0:
                         output +=  block
                    else:
                        output += block[0:(offset+length)%4096] #going only until last block trim
                else:
                    output +=  block #all
                #print("output_length :",len(output))
                #If the file does not exist in the cloud, or the offset has exceeded the end of the file, return a byte array with 0 byte.
                #If the cloud does not contain the unique block key = if the file does not exist in cloud
                
                #how do we check if the file does not exist in cloud or the offset has exceeded the end of the file? Do we need to check for this?
    
        return output
    
    def write(self, fd, data, offset):
        #Write the data store in a byte array into the opened file descriptor, at the given offset. 
        #No return value is needed. The function should always succeed. If the file is previously written 
        #and the newly written offset and length have overlapped with the original file size, the overlapped data will 
        #be overwritten. You must implement in-place updating to handle this corner case.

        # filename = self.fds[fd]
        # align_offset =  int(offset/4096) 
        # cloud_picked, block_offset = self.get_cloud_from_hash_map(str(filename)+str(align_offset))
        # cloud_picked[0].write_block(data,block_offset)

        #Algo
        #-> convert data  -> bytearray; offset -> input
        #-> len = len(data byte array)
        #-> start_block= int(offset/4096)
        #-> ending_block = int(offset+len/4096)
        #-> no_of_blocks = start_block - ending_block + 1
        #-> x = 0
        #-> for i each block
        #->    cloud, block_offset = hashing function(filename, start_block+i)
        #->    output = cloud.read_block(block_offset)
        #->    if first block i=0:
        #->         x = 4096-offset
        #->         output[offset%4096:] = data[0:x]
        #->    else if last block:
        #->         output[0:(offset+len)%4096] = data[x:]
        #->         #Add the case for offset+len being divisible by 4096 
        #->    else next blocks:
        #->         output = data[x:x+4096]
        #->         x = x+4096
        #->    write the output to cloud    
    
        
        filename = self.fds[fd]
        d = bytearray(data)
        length = len(d)
        start_block = int(offset/4096)
        ending_block = int((offset+length)/4096)
        no_of_blocks = ending_block - start_block + 1
        
        x = 0
        for i in range(no_of_blocks):
          cloud_picked, block_offset = self.get_cloud_from_hash_map(str(filename)+str(start_block+i))
          if i == 0:
                x = 4096-(offset%4096)
          
          for c in cloud_picked:
                existing_blocks = c.list_blocks()
                if block_offset in existing_blocks:
                    block = c.read_block(block_offset)
                else:
                    block = bytearray()
                if i == 0:
                    #print("First block", len(data[0:x]))
                    block[offset%4096:] = data[0:x]
                elif i == no_of_blocks-1:
                    #print("Last Block", len(data[x:x+4096]))
                    if ((offset+length)%4096) == 0:
                        block = data[x:]
                    else:
                        block[0:((offset+length)%4096)] = data[x:]
                else:
                    #print("Middle Block", len(data[x:x+4096]))
                    block[0:4096] = data[x:x+4096]
                c.write_block(block,block_offset)
                
          if i > 0:
                x = x+4096 
    
    def delete(self, filename):
        
        blocks_exist = True
        i = 0
        
        while blocks_exist:
            
            cloud_picked, block_offset = self.get_cloud_from_hash_map(str(filename)+str(i))
            for c in cloud_picked:
                if block_offset in c.list_blocks():
                    c.delete_block(block_offset)
                else:
                    blocks_exist = False
                    break
            i = i + 1
    
    def close(self, fd):
        
        #Simply close the file and deallocate the file descriptor. 
        #This function should always return successfully as long as the given file descriptor is valid.
        if fd not in self.fds:
            raise IOError("File descriptor %d does not exist." % fd)
        del self.fds[fd]
        return

# from basic_defs import cloud_storage, NAS

# import os
# import sys

# class AWS_S3(cloud_storage):
#     def __init__(self):
#         # TODO: Fill in the AWS access key ID
#         self.access_key_id = ""
#         # TODO: Fill in the AWS access secret key
#         self.access_secret_key = ""
#         # TODO: Fill in the bucket name
#         self.bucket_name = ""

#     # Implement the abstract functions from cloud_storage
#     # Hints: Use the following APIs from boto3
#     #     boto3.session.Session:
#     #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/core/session.html
#     #     boto3.resources:
#     #         https://boto3.amazonaws.com/v1/documentation/api/latest/guide/resources.html
#     #     boto3.s3.Bucket:
#     #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#bucket
#     #     boto3.s3.Object:
#     #         https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html#object

# class Azure_Blob_Storage(cloud_storage):
#     def __init__(self):
#         # TODO: Fill in the Azure key
#         self.key = ""
#         # TODO: Fill in the Azure connection string
#         self.conn_str = ""
#         # TODO: Fill in the account name
#         self.account_name = "csce678s21"
#         # TODO: Fill in the container name
#         self.container_name = ""

#     # Implement the abstract functions from cloud_storage
#     # Hints: Use the following APIs from azure.storage.blob
#     #    blob.BlobServiceClient:
#     #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobserviceclient?view=azure-python
#     #    blob.ContainerClient:
#     #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.containerclient?view=azure-python
#     #    blob.BlobClient:
#     #        https://docs.microsoft.com/en-us/python/api/azure-storage-blob/azure.storage.blob.blobclient?view=azure-python

# class Google_Cloud_Storage(cloud_storage):
#     def __init__(self):
#         # Google Cloud Storage is authenticated with a **Service Account**
#         # TODO: Download and place the Credential JSON file
#         self.credential_file = "gcp-credential.json"
#         # TODO: Fill in the container name
#         self.bucket_name = ""

#     # Implement the abstract functions from cloud_storage
#     # Hints: Use the following APIs from google.cloud.storage
#     #    storage.client.Client:
#     #        https://googleapis.dev/python/storage/latest/client.html
#     #    storage.bucket.Bucket:
#     #        https://googleapis.dev/python/storage/latest/buckets.html
#     #    storage.blob.Blob:
#     #        https://googleapis.dev/python/storage/latest/blobs.html

# class RAID_on_Cloud(NAS):
#     def __init__(self):
#         self.backends = [
#                 AWS_S3(),
#                 Azure_Blob_Storage(),
#                 Google_Cloud_Storage()
#             ]

#     # Implement the abstract functions from NAS

