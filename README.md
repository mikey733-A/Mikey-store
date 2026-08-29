# MIKEY STORE Production v2

## Included
- PostgreSQL through SQLAlchemy
- Secure admin login using a password hash (no plaintext password)
- CSRF protection on admin writes
- Login and order rate limits
- Product create/edit/hide
- Product image uploads: Cloudinary in production, local fallback for development
- Inventory checks and order records
- Hosted Tranzila iFrame checkout
- Optional Tranzila Handshake V2
- Payment webhook that verifies the transaction server-to-server before marking an order paid
- Dockerfile, Gunicorn, Render Blueprint and health check

## Generate admin password hash
python generate_password_hash.py
Copy the output into ADMIN_PASSWORD_HASH.

## Required environment variables
SECRET_KEY
ADMIN_USER
ADMIN_PASSWORD_HASH
PUBLIC_URL
WHATSAPP_NUMBER
DATABASE_URL

For Tranzila:
TRANZILA_TERMINAL
TRANZILA_APP_KEY
TRANZILA_SECRET
TRANZILA_HANDSHAKE_ENABLED=false

For production image uploads:
CLOUDINARY_CLOUD_NAME
CLOUDINARY_API_KEY
CLOUDINARY_API_SECRET

## Deploy to Render
1. Push this folder to GitHub.
2. In Render create a Blueprint from render.yaml.
3. Enter all `sync: false` secrets in Render.
4. Set PUBLIC_URL to your final HTTPS URL.
5. Add your custom domain if desired.
6. In Tranzila configure the Notify URL as:
   https://YOUR-DOMAIN/payment/notify
7. Test approved and declined transactions before launch.

## Payment security
The redirect success page never marks an order as paid. Only the server-to-server notify endpoint can do that, and it calls Tranzila's transaction API to verify the transaction amount and result before updating the order.

Handshake V2 is optional because Tranzila documents that it requires the Token Module. Only enable TRANZILA_HANDSHAKE_ENABLED after your terminal has that feature enabled.

## Images
Cloudinary is recommended for production because app filesystem uploads can be ephemeral on many hosting platforms. Local uploads remain available for development.

## Before launch
- Add privacy, terms, shipping and returns pages.
- Enable database backups.
- Test webhook retries/idempotency.
- Confirm your Tranzila terminal field names/settings with your merchant account.
- Never store PAN/CVV/card data.
