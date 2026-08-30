from getpass import getpass
from werkzeug.security import generate_password_hash
pw=getpass("Admin password:majed12 ")
print(generate_password_hash(pw))
