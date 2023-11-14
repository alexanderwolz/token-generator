Keys generated using:

openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
openssl pkcs8 -in private.pem -topk8 -nocrypt -out private-pkcs8.pem

Info: First key is PKCS1 but Java only knows PKCS8, so we need to create one in this format