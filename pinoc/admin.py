"""Local administration CLI; passwords and token secrets never enter the database in plaintext."""
import argparse,getpass,json,os
from pinoc.database import Database
from pinoc.security import SecurityManager
def main():
 p=argparse.ArgumentParser();p.add_argument("--database",default=os.getenv("PINOC_DATABASE_PATH","data/pinoc.db"));s=p.add_subparsers(dest="command",required=True)
 for name in ("create-user","reset-password","disable-user"):
  x=s.add_parser(name);x.add_argument("username");x.add_argument("--role",choices=("viewer","operator","administrator"),default="viewer")
 s.add_parser("list-users")
 x=s.add_parser("create-token");x.add_argument("owner");x.add_argument("--scope",action="append",required=True)
 x=s.add_parser("revoke-token");x.add_argument("token_id")
 a=p.parse_args();db=Database(a.database)
 if not db.initialize():raise SystemExit(db.error)
 sec=SecurityManager(db,True)
 if a.command=="create-user":sec.create_user(a.username,getpass.getpass("Password: "),a.role)
 elif a.command=="reset-password":
  from werkzeug.security import generate_password_hash
  password=getpass.getpass("New password: ")
  if len(password)<10:raise SystemExit("password must contain at least 10 characters")
  db.execute("UPDATE users SET password_hash=? WHERE username=?",(generate_password_hash(password),a.username))
 elif a.command=="disable-user":db.execute("UPDATE users SET enabled=0 WHERE username=?",(a.username,))
 elif a.command=="list-users":print(json.dumps(db.rows("SELECT username,role,enabled,created_at,last_login FROM users ORDER BY username"),indent=2))
 elif a.command=="create-token":print(sec.create_token(a.owner,a.scope))
 else:db.execute("UPDATE api_tokens SET enabled=0 WHERE token_id=?",(a.token_id,))
if __name__=="__main__":main()
