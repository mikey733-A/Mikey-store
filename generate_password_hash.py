from getpass import getpass
from werkzeug.security import generate_password_hash
pw=getpass("Admin password: ")
print(generate_password_hash(pw))
