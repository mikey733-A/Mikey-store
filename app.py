
import os, secrets, hmac, hashlib, time, json
from decimal import Decimal
from urllib.parse import quote

import requests
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
)

db_url = os.environ.get("DATABASE_URL", "sqlite:///mikey_store.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = db_url

db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per hour"], storage_uri="memory://")

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")
WHATSAPP_NUMBER = os.environ.get("WHATSAPP_NUMBER", "")
PUBLIC_URL = os.environ.get("PUBLIC_URL", "http://localhost:5000").rstrip("/")

TRANZILA_TERMINAL = os.environ.get("TRANZILA_TERMINAL", "")
TRANZILA_APP_KEY = os.environ.get("TRANZILA_APP_KEY", "")
TRANZILA_SECRET = os.environ.get("TRANZILA_SECRET", "")
TRANZILA_HANDSHAKE_ENABLED = os.environ.get("TRANZILA_HANDSHAKE_ENABLED", "false").lower() == "true"

CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME", "")
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY", "")
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET", "")

ALLOWED_EXTENSIONS = {"png","jpg","jpeg","webp"}

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(80), nullable=False)
    description = db.Column(db.Text, default="")
    price = db.Column(db.Numeric(10,2), nullable=False)
    old_price = db.Column(db.Numeric(10,2))
    image = db.Column(db.String(700), default="")
    stock = db.Column(db.Integer, default=0, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    phone = db.Column(db.String(40), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(300), nullable=False)
    payment_method = db.Column(db.String(40), nullable=False)
    subtotal = db.Column(db.Numeric(10,2), nullable=False)
    shipping = db.Column(db.Numeric(10,2), nullable=False)
    total = db.Column(db.Numeric(10,2), nullable=False)
    status = db.Column(db.String(30), default="new", nullable=False)
    payment_status = db.Column(db.String(30), default="unpaid", nullable=False)
    transaction_id = db.Column(db.String(100), unique=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("order.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("product.id"))
    name = db.Column(db.String(200), nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

def csrf_token():
    token = session.get("_csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf"] = token
    return token

@app.context_processor
def inject_globals():
    return {"csrf_token": csrf_token()}

def require_csrf():
    supplied = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
    expected = session.get("_csrf", "")
    if not supplied or not expected or not hmac.compare_digest(supplied, expected):
        abort(400, "CSRF validation failed")

def admin_required():
    if not session.get("admin"):
        abort(403)

def allowed_image(filename):
    return "." in filename and filename.rsplit(".",1)[1].lower() in ALLOWED_EXTENSIONS

def save_image(file):
    if not file or not file.filename:
        return None
    if not allowed_image(file.filename):
        raise ValueError("صيغة الصورة غير مدعومة")
    if CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET:
        import cloudinary, cloudinary.uploader
        cloudinary.config(
            cloud_name=CLOUDINARY_CLOUD_NAME,
            api_key=CLOUDINARY_API_KEY,
            api_secret=CLOUDINARY_API_SECRET,
            secure=True,
        )
        result = cloudinary.uploader.upload(
            file,
            folder="mikey-store/products",
            resource_type="image",
            transformation=[{"width":1200,"height":1200,"crop":"limit","quality":"auto","fetch_format":"auto"}]
        )
        return result["secure_url"]
    filename = f"{secrets.token_hex(8)}-{secure_filename(file.filename)}"
    file.save(os.path.join(app.root_path, "static", "uploads", filename))
    return url_for("static", filename=f"uploads/{filename}")

def tranzila_auth_headers():
    if not TRANZILA_APP_KEY or not TRANZILA_SECRET:
        raise RuntimeError("Tranzila API credentials missing")
    ts = str(int(time.time()))
    nonce = secrets.token_hex(40)
    token = hmac.new(
        (TRANZILA_SECRET + ts + nonce).encode(),
        TRANZILA_APP_KEY.encode(),
        hashlib.sha256,
    ).hexdigest()
    return {
        "Content-Type":"application/json",
        "X-tranzila-api-app-key":TRANZILA_APP_KEY,
        "X-tranzila-api-request-time":ts,
        "X-tranzila-api-nonce":nonce,
        "X-tranzila-api-access-token":token,
    }

def create_handshake(order):
    payload = {
        "terminal_name": TRANZILA_TERMINAL,
        "sum": float(order.total),
        "request_params": {"order_id": str(order.id)},
    }
    r = requests.post(
        "https://api.tranzila.com/v2/handshake/create",
        headers=tranzila_auth_headers(),
        json=payload,
        timeout=15,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("error_code") != 0 or not data.get("thtk"):
        raise RuntimeError(data.get("message","Handshake failed"))
    return data["thtk"]

def verify_transaction_with_tranzila(transaction_index, order):
    if not (TRANZILA_APP_KEY and TRANZILA_SECRET and TRANZILA_TERMINAL):
        return False
    payload = {"terminal_name": TRANZILA_TERMINAL, "transaction_index": int(transaction_index)}
    r = requests.post(
        "https://api.tranzila.com/v1/transactions",
        headers=tranzila_auth_headers(),
        json=payload,
        timeout=15,
    )
    if not r.ok:
        return False
    data = r.json()
    txs = data.get("transactions") or data.get("transaction") or []
    if isinstance(txs, dict):
        txs = [txs]
    if not txs:
        return False
    tx = txs[0]
    amount = tx.get("amount") or tx.get("sum")
    try:
        if Decimal(str(amount)).quantize(Decimal("0.01")) != Decimal(order.total).quantize(Decimal("0.01")):
            return False
    except Exception:
        return False
    terminal = tx.get("terminal_name")
    if terminal and terminal != TRANZILA_TERMINAL:
        return False
    response = str(tx.get("response") or tx.get("processor_response_code") or tx.get("Response") or "")
    if response and response not in {"000","0"}:
        return False
    return True

def seed():
    db.create_all()
    if Product.query.count() == 0:
        examples = [
            ("منظم سيارة عملي","السيارة","منتج عملي للاستخدام اليومي داخل السيارة",129,159,"🚗",20),
            ("أداة منزلية ذكية","المنزل","أداة بسيطة للمنزل",99,129,"🏠",25),
            ("إكسسوار أنيق","إكسسوارات","إكسسوار عملي وأنيق",79,99,"✨",30),
        ]
        for x in examples:
            db.session.add(Product(name=x[0],category=x[1],description=x[2],price=x[3],old_price=x[4],image=x[5],stock=x[6]))
        db.session.commit()

@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-src https://direct.tranzila.com https://directng.tranzila.com; "
        "connect-src 'self'; form-action 'self' https://direct.tranzila.com https://directng.tranzila.com"
    )
    return resp

@app.get("/health")
def health():
    db.session.execute(db.text("SELECT 1"))
    return {"ok":True}

@app.get("/")
def home():
    return render_template("store.html", products=Product.query.filter_by(active=True).order_by(Product.id.desc()).all())

@app.post("/api/orders")
@limiter.limit("30 per hour")
def create_order():
    data = request.get_json(silent=True) or {}
    items = data.get("items", [])
    if not items or any(not str(data.get(k,"")).strip() for k in ["name","phone","city","address"]):
        return jsonify(error="بيانات الطلب غير مكتملة"), 400

    verified, subtotal = [], Decimal("0")
    for item in items:
        try:
            pid, qty = int(item["id"]), int(item["quantity"])
        except Exception:
            return jsonify(error="طلب غير صالح"), 400
        p = db.session.get(Product, pid)
        if not p or not p.active or qty < 1 or qty > p.stock:
            return jsonify(error=f"المنتج غير متوفر بالكمية المطلوبة"), 400
        subtotal += Decimal(p.price) * qty
        verified.append((p,qty))

    shipping = Decimal("25.00") if subtotal else Decimal("0")
    total = subtotal + shipping
    payment_method = data.get("payment_method","cod")
    if payment_method not in {"cod","card"}:
        return jsonify(error="طريقة الدفع غير صالحة"),400

    order = Order(
        name=data["name"].strip()[:160], phone=data["phone"].strip()[:40],
        city=data["city"].strip()[:100], address=data["address"].strip()[:300],
        payment_method=payment_method, subtotal=subtotal, shipping=shipping, total=total,
        status="pending_payment" if payment_method=="card" else "new",
    )
    db.session.add(order); db.session.flush()
    for p,qty in verified:
        db.session.add(OrderItem(order_id=order.id,product_id=p.id,name=p.name,price=p.price,quantity=qty))
        p.stock -= qty
    db.session.commit()

    wa = ""
    if WHATSAPP_NUMBER and payment_method=="cod":
        msg = f"طلب MIKEY STORE #{order.id}\nالاسم: {order.name}\nالهاتف: {order.phone}\nالمدينة: {order.city}\nالعنوان: {order.address}\nالإجمالي: {order.total} ₪"
        wa = f"https://wa.me/{WHATSAPP_NUMBER}?text={quote(msg)}"

    return jsonify(
        order_id=order.id, total=float(order.total), whatsapp=wa,
        payment_url=url_for("pay",order_id=order.id) if payment_method=="card" else ""
    )

@app.route("/pay/<int:order_id>", methods=["GET","POST"])
def pay(order_id):
    order = db.session.get(Order, order_id)
    if not order or order.payment_method != "card":
        abort(404)
    if order.payment_status == "paid":
        return redirect(url_for("payment_success", order_id=order.id))
    if not TRANZILA_TERMINAL:
        return "بوابة الدفع غير مهيأة. أضف بيانات Tranzila في Environment Variables.", 503

    thtk = ""
    if TRANZILA_HANDSHAKE_ENABLED:
        try:
            thtk = create_handshake(order)
        except Exception as e:
            app.logger.exception("Handshake failed")
            return "تعذر بدء عملية الدفع الآمن.", 502

    return render_template(
        "pay.html",
        order=order,
        terminal=TRANZILA_TERMINAL,
        notify_url=f"{PUBLIC_URL}/payment/notify",
        success_url=f"{PUBLIC_URL}/payment/success/{order.id}",
        failure_url=f"{PUBLIC_URL}/payment/failure/{order.id}",
        thtk=thtk,
    )

@app.post("/payment/notify")
@limiter.exempt
def payment_notify():
    form = request.form.to_dict(flat=True)
    try:
        order_id = int(form.get("myid") or form.get("order_id") or "0")
        transaction_index = int(form.get("transaction_id") or form.get("transaction_index") or "0")
        response_code = str(form.get("Response") or form.get("response") or "")
        amount = Decimal(str(form.get("sum") or form.get("amount") or "0")).quantize(Decimal("0.01"))
    except Exception:
        return "BAD", 400

    order = db.session.get(Order, order_id)
    if not order:
        return "BAD", 404
    if amount != Decimal(order.total).quantize(Decimal("0.01")):
        app.logger.warning("Webhook amount mismatch for order %s", order_id)
        return "BAD", 400
    if response_code not in {"000","0"}:
        order.payment_status = "failed"
        db.session.commit()
        return "OK", 200

    # Do not trust browser redirects or form fields alone.
    # Confirm the transaction server-to-server with Tranzila's transaction API.
    if not transaction_index or not verify_transaction_with_tranzila(transaction_index, order):
        app.logger.warning("Webhook verification failed for order %s", order_id)
        return "BAD", 400

    existing = Order.query.filter(Order.transaction_id == str(transaction_index), Order.id != order.id).first()
    if existing:
        return "BAD", 409

    order.payment_status = "paid"
    order.status = "processing"
    order.transaction_id = str(transaction_index)
    db.session.commit()
    return "OK", 200

@app.get("/payment/success/<int:order_id>")
def payment_success(order_id):
    order = db.session.get(Order, order_id) or abort(404)
    return render_template("result.html", ok=True, order=order)

@app.get("/payment/failure/<int:order_id>")
def payment_failure(order_id):
    order = db.session.get(Order, order_id) or abort(404)
    return render_template("result.html", ok=False, order=order)

@app.route("/admin/login", methods=["GET","POST"])
@limiter.limit("10 per minute")
def admin_login():
    error = ""
    if request.method == "POST":
        require_csrf()
        valid_user = hmac.compare_digest(request.form.get("username",""), ADMIN_USER)
        valid_pass = bool(ADMIN_PASSWORD_HASH) and check_password_hash(ADMIN_PASSWORD_HASH, request.form.get("password",""))
        if valid_user and valid_pass:
            session.clear()
            session["admin"] = True
            session["_csrf"] = secrets.token_urlsafe(32)
            return redirect(url_for("admin"))
        error = "بيانات الدخول غير صحيحة"
    return render_template("login.html", error=error)

@app.post("/admin/logout")
def admin_logout():
    admin_required(); require_csrf()
    session.clear()
    return redirect(url_for("admin_login"))

@app.get("/admin")
def admin():
    if not session.get("admin"):
        return redirect(url_for("admin_login"))
    products = Product.query.order_by(Product.id.desc()).all()
    orders = Order.query.order_by(Order.id.desc()).limit(200).all()
    revenue = db.session.query(db.func.coalesce(db.func.sum(Order.total),0)).filter(Order.payment_status=="paid").scalar()
    return render_template("admin.html", products=products, orders=orders, revenue=revenue)

@app.post("/admin/products/add")
@limiter.limit("60 per hour")
def add_product():
    admin_required(); require_csrf()
    f = request.form
    image = save_image(request.files.get("image_file")) or f.get("image_url","").strip() or "📦"
    p = Product(
        name=f["name"].strip(), category=f["category"].strip(), description=f.get("description","").strip(),
        price=Decimal(f["price"]), old_price=Decimal(f["old_price"]) if f.get("old_price") else None,
        image=image, stock=int(f["stock"]), active=True
    )
    db.session.add(p); db.session.commit()
    return redirect(url_for("admin"))

@app.route("/admin/products/<int:pid>/edit", methods=["GET","POST"])
def edit_product(pid):
    admin_required()
    p = db.session.get(Product,pid) or abort(404)
    if request.method=="POST":
        require_csrf(); f=request.form
        uploaded = save_image(request.files.get("image_file"))
        p.name=f["name"].strip(); p.category=f["category"].strip(); p.description=f.get("description","").strip()
        p.price=Decimal(f["price"]); p.old_price=Decimal(f["old_price"]) if f.get("old_price") else None
        p.stock=max(0,int(f["stock"])); p.active=f.get("active")=="on"
        if uploaded: p.image=uploaded
        elif f.get("image_url","").strip(): p.image=f["image_url"].strip()
        db.session.commit()
        return redirect(url_for("admin"))
    return render_template("edit_product.html", p=p)

@app.post("/admin/products/<int:pid>/delete")
def delete_product(pid):
    admin_required(); require_csrf()
    p=db.session.get(Product,pid) or abort(404)
    p.active=False; db.session.commit()
    return redirect(url_for("admin"))

@app.post("/admin/orders/<int:oid>/status")
def order_status(oid):
    admin_required(); require_csrf()
    o=db.session.get(Order,oid) or abort(404)
    status=request.form.get("status")
    if status not in {"new","pending_payment","processing","shipped","completed","cancelled"}:
        abort(400)
    o.status=status; db.session.commit()
    return redirect(url_for("admin"))

with app.app_context():
    seed()

if __name__ == "__main__":
    app.run()
