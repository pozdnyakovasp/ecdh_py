import base64
import codecs
import sslcrypto
import logging
import urllib.parse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    b64_string = urllib.parse.unquote(event["queryStringParameters"]["message"])
    logger.info('Recieved b64_string from client: ' + b64_string)
    input = base64.b64decode(b64_string)

    # test public key for private key inside example
    # pubkey = "04d08e67c1371b7201aabf03b933c23b540cce0c007a59137f50d70bb4cc5ebd860344af03a47b6bb503b05952200d264c5f8fee57d54da40cd38cb7b004c629c5"
    pubkey = "04e6f4614fbc77d7edfc9d5cfe1e2d2499f4afe57726834cfa62020d52e5b7d2795622fdf46b6ff33e92d0c3e56083a88129d6e062ff583213a9731990ce846737"
    pk_bin = codecs.decode(pubkey, "hex")
    curve = sslcrypto.ecc.get_curve("prime256v1")
    result = curve.encrypt(input, pk_bin, derivation=None, mac=None)
    #result = base64.b64encode(result).decode('ascii')
    result = base64.urlsafe_b64encode(result).decode('ascii')

    return {
        'statusCode': 200,
        'body': result
    }
