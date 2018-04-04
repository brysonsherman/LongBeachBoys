import json

from base64 import b64decode, b64encode

def loadFileFromJSON(filepath):

    with open(filepath, 'r') as json_file:
        data = json.load(json_file)

    key = b64decode(data["Key"])
    iv = b64decode(data["IV"])
    text = b64decode(data["Text"])
    ext = data["Extension"]
    tag = b64decode(data["Tag"])

    json_file.close()
    return (text, key, iv, tag, ext)

def saveFileAsJSON (saveFilePath, text, iv, key, tag, ext):

    data = {
        'IV': b64encode(iv).decode('utf-8'),
        'Key': b64encode(key).decode('utf-8'),
        'Text': b64encode(text).decode('utf-8'),
        'Extension': ext,
        'Tag': b64encode(tag).decode('utf-8')
        }

    with open(saveFilePath, 'w') as outFile:
        json.dump(data, outFile)
    outFile.close()

def saveFile(filename, plaintext, ext):

    with open(filename + ext, "wb") as sFile:
        sFile.write(plaintext)
    sFile.close()
