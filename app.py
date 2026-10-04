import os
import secrets
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from PIL import Image, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("ECLIPSE_DATA_DIR", BASE_DIR)).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR = (
    DATA_DIR / "uploads"
    if os.environ.get("ECLIPSE_DATA_DIR")
    else BASE_DIR / "static" / "uploads"
)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


def load_secret_key():
    """Keep local sessions valid across app restarts with a private on-disk key."""
    configured_key = os.environ.get("ECLIPSE_SECRET_KEY")
    if configured_key:
        return configured_key
    key_file = DATA_DIR / ".eclipse_secret_key"
    try:
        return key_file.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        key = secrets.token_urlsafe(48)
        try:
            key_file.write_text(key, encoding="utf-8")
        except FileExistsError:
            return key_file.read_text(encoding="utf-8").strip()
        return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    DATABASE=str(DATA_DIR / "eclipse.db"),
    UPLOAD_FOLDER=str(UPLOAD_DIR),
    MAX_CONTENT_LENGTH=8 * 1024 * 1024,
    ADMIN_EMAIL=os.environ.get("ECLIPSE_ADMIN_EMAIL", "").strip().lower(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("ECLIPSE_COOKIE_SECURE") == "1",
)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_IMAGE_PIXELS = 20_000_000


@app.get("/uploads/<path:filename>")
def uploaded_image(filename):
    return send_from_directory(UPLOAD_DIR, filename)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], timeout=10)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at TEXT NOT NULL,
      bio TEXT NOT NULL DEFAULT '', avatar TEXT NOT NULL DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS boards (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL, description TEXT DEFAULT '', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pins (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL, description TEXT DEFAULT '', image TEXT NOT NULL,
      link TEXT DEFAULT '', created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS saved_pins (
      pin_id INTEGER NOT NULL REFERENCES pins(id) ON DELETE CASCADE,
      board_id INTEGER NOT NULL REFERENCES boards(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL, PRIMARY KEY(pin_id, board_id)
    );
    CREATE TABLE IF NOT EXISTS likes (
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      pin_id INTEGER NOT NULL REFERENCES pins(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL, PRIMARY KEY(user_id, pin_id)
    );
    CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      pin_id INTEGER NOT NULL REFERENCES pins(id) ON DELETE CASCADE,
      body TEXT NOT NULL, created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS follows (
      follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      followed_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TEXT NOT NULL, PRIMARY KEY(follower_id, followed_id),
      CHECK(follower_id != followed_id)
    );
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      pin_id INTEGER NOT NULL REFERENCES pins(id) ON DELETE CASCADE,
      reason TEXT NOT NULL, details TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'open', created_at TEXT NOT NULL,
      UNIQUE(reporter_id, pin_id)
    );
    CREATE INDEX IF NOT EXISTS pins_created ON pins(created_at DESC);
    CREATE INDEX IF NOT EXISTS comments_pin ON comments(pin_id, created_at DESC);
    """)
    columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "bio" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN bio TEXT NOT NULL DEFAULT ''")
    if "avatar" not in columns:
        db.execute("ALTER TABLE users ADD COLUMN avatar TEXT NOT NULL DEFAULT ''")
    db.commit()
    db.execute("PRAGMA journal_mode = WAL")
    db.commit()


with app.app_context():
    init_db()


@app.before_request
def prepare_request():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    g.user = None
    if session.get("user_id"):
        g.user = get_db().execute("SELECT id, username, email, bio, avatar FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.context_processor
def template_context():
    user = getattr(g, "user", None)
    is_admin = bool(user and app.config["ADMIN_EMAIL"] and user["email"].lower() == app.config["ADMIN_EMAIL"])
    return {"current_user": user, "is_admin": is_admin, "csrf_token": session.get("csrf_token", "")}


@app.before_request
def csrf_protect():
    if request.method == "POST" and request.form.get("csrf_token") != session.get("csrf_token"):
        abort(400, "The form expired. Please refresh and try again.")


@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' https: data:; "
        "style-src 'self' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; form-action 'self'; "
        "base-uri 'self'; frame-ancestors 'none'",
    )
    if os.environ.get("ECLIPSE_COOKIE_SECURE") == "1":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please sign in to do that.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fetch_pins(query=""):
    db = get_db()
    liked_expression = (
        "EXISTS(SELECT 1 FROM likes mine WHERE mine.pin_id=p.id AND mine.user_id=?)"
        if g.user else "0"
    )
    params = [g.user["id"]] if g.user else []
    sql = f"""SELECT p.*, u.username,
      (SELECT COUNT(*) FROM saved_pins s WHERE s.pin_id=p.id) AS saves,
      (SELECT COUNT(*) FROM likes l WHERE l.pin_id=p.id) AS likes,
      (SELECT COUNT(*) FROM comments c WHERE c.pin_id=p.id) AS comment_count,
      {liked_expression} AS liked
      FROM pins p JOIN users u ON u.id=p.user_id"""
    if query:
        sql += " WHERE p.title LIKE ? OR p.description LIKE ? OR u.username LIKE ?"
        params.extend([f"%{query}%"] * 3)
    sql += " ORDER BY p.created_at DESC"
    return db.execute(sql, params).fetchall()


def store_image(upload):
    """Validate image bytes and re-encode them before storing user uploads."""
    extension = Path(upload.filename or "").suffix.lower().lstrip(".")
    if extension not in ALLOWED_EXTENSIONS:
        return None
    try:
        upload.stream.seek(0)
        with Image.open(upload.stream) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS:
                return None
            image.verify()
        upload.stream.seek(0)
        with Image.open(upload.stream) as image:
            image.seek(0)
            if image.width * image.height > MAX_IMAGE_PIXELS:
                return None
            image = image.convert("RGB")
            filename = f"{secrets.token_hex(16)}.webp"
            image.save(UPLOAD_DIR / filename, format="WEBP", quality=88, method=6)
            return url_for("uploaded_image", filename=filename)
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError, ValueError):
        return None


def remove_uploaded_image_if_unused(db, image):
    prefixes = ("/uploads/", url_for("static", filename="uploads/"))
    if not any(image.startswith(prefix) for prefix in prefixes):
        return
    if db.execute("SELECT 1 FROM pins WHERE image=? LIMIT 1", (image,)).fetchone():
        return
    image_path = UPLOAD_DIR / Path(image).name
    if image_path.parent == UPLOAD_DIR and image_path.is_file():
        image_path.unlink()


@app.route("/")
def index():
    query = request.args.get("q", "").strip()[:100]
    return render_template("index.html", pins=fetch_pins(query), query=query)


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 30 or not username.replace("_", "").isalnum():
            flash("Choose a username with 3–30 letters, numbers, or underscores.", "error")
        elif "@" not in email or len(email) > 254:
            flash("Enter a valid email address.", "error")
        elif len(password) < 10 or len(password) > 128:
            flash("Choose a password between 10 and 128 characters.", "error")
        else:
            db = get_db()
            try:
                cur = db.execute("INSERT INTO users(username,email,password,created_at) VALUES(?,?,?,?)",
                                  (username, email, generate_password_hash(password), timestamp()))
                user_id = cur.lastrowid
                db.execute("INSERT INTO boards(user_id,name,description,created_at) VALUES(?,?,?,?)",
                           (user_id, "Favorites", "Your saved inspiration", timestamp()))
                db.commit()
                session.clear()
                session["user_id"] = user_id
                session["csrf_token"] = secrets.token_urlsafe(24)
                return redirect(url_for("index"))
            except sqlite3.IntegrityError:
                db.rollback()
                flash("That username or email is already in use.", "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("index"))
    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        user = get_db().execute("SELECT * FROM users WHERE email=? OR username=?", (identity.lower(), identity)).fetchone()
        password = request.form.get("password", "")
        if user and len(password) <= 128 and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(24)
            destination = request.args.get("next", "")
            return redirect(destination if destination.startswith("/") and not destination.startswith("//") else url_for("index"))
        flash("We couldn't match those sign-in details.", "error")
    return render_template("auth.html", mode="login")


@app.post("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/create", methods=["GET", "POST"])
@login_required
def create_pin():
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:120]
        description = request.form.get("description", "").strip()[:1000]
        link = request.form.get("link", "").strip()[:500]
        image_url = request.form.get("image_url", "").strip()
        upload = request.files.get("image")
        image = None
        if upload and upload.filename:
            image = store_image(upload)
            if not image:
                flash("Choose a valid PNG, JPG, GIF, or WebP image under 20 megapixels.", "error")
        elif image_url.startswith(("https://", "http://")):
            image = image_url
        elif image_url:
            flash("Image links need to start with http:// or https://.", "error")
        if not title:
            flash("Add a title for your pin.", "error")
        elif not image:
            if not (upload and upload.filename):
                flash("Choose an image to upload or add an image URL.", "error")
        else:
            if link and not link.startswith(("https://", "http://")):
                link = "https://" + link
            cur = get_db().execute("INSERT INTO pins(user_id,title,description,image,link,created_at) VALUES(?,?,?,?,?,?)",
                                   (g.user["id"], title, description, image, link, timestamp()))
            get_db().commit()
            flash("Your pin is live!", "success")
            return redirect(url_for("pin_detail", pin_id=cur.lastrowid))
        if image and not title:
            remove_uploaded_image_if_unused(get_db(), image)
    return render_template("create.html")


@app.route("/pins/<int:pin_id>")
def pin_detail(pin_id):
    db = get_db()
    pin = db.execute("""SELECT p.*,u.username,
      (SELECT COUNT(*) FROM likes l WHERE l.pin_id=p.id) AS like_count,
      (SELECT COUNT(*) FROM saved_pins s WHERE s.pin_id=p.id) AS saves,
      (SELECT COUNT(*) FROM comments c WHERE c.pin_id=p.id) AS comment_count
      FROM pins p JOIN users u ON u.id=p.user_id WHERE p.id=?""", (pin_id,)).fetchone()
    if not pin:
        abort(404)
    boards = []
    saved = False
    saved_board_id = None
    saved_board_ids = set()
    liked = False
    if g.user:
        boards = db.execute("SELECT * FROM boards WHERE user_id=? ORDER BY name", (g.user["id"],)).fetchall()
        saved_entries = db.execute("SELECT s.board_id FROM saved_pins s JOIN boards b ON b.id=s.board_id WHERE s.pin_id=? AND b.user_id=? ORDER BY s.created_at", (pin_id, g.user["id"])).fetchall()
        saved_board_ids = {entry["board_id"] for entry in saved_entries}
        saved_entry = saved_entries[0] if saved_entries else None
        saved_board_id = saved_entry["board_id"] if saved_entry else None
        saved = bool(saved_board_ids)
        liked = db.execute("SELECT 1 FROM likes WHERE pin_id=? AND user_id=?", (pin_id, g.user["id"])).fetchone() is not None
    comments = db.execute("SELECT c.*,u.username FROM comments c JOIN users u ON u.id=c.user_id WHERE c.pin_id=? ORDER BY c.created_at DESC", (pin_id,)).fetchall()
    return render_template("pin.html", pin=pin, boards=boards, saved=saved, saved_board_id=saved_board_id, saved_board_ids=saved_board_ids, liked=liked, comments=comments)


@app.route("/pins/<int:pin_id>/edit", methods=["GET", "POST"])
@login_required
def edit_pin(pin_id):
    db = get_db()
    pin = db.execute("SELECT * FROM pins WHERE id=? AND user_id=?", (pin_id, g.user["id"])).fetchone()
    if not pin:
        abort(404)
    if request.method == "POST":
        title = request.form.get("title", "").strip()[:120]
        description = request.form.get("description", "").strip()[:1000]
        link = request.form.get("link", "").strip()[:500]
        upload = request.files.get("image")
        image = store_image(upload) if upload and upload.filename else pin["image"]
        if link and not link.startswith(("https://", "http://")):
            link = "https://" + link
        if not title:
            flash("Add a title for your pin.", "error")
        elif not image:
            flash("That image could not be read. Try a PNG, JPG, GIF, or WebP image.", "error")
        else:
            old_image = pin["image"]
            db.execute("UPDATE pins SET title=?,description=?,link=?,image=? WHERE id=?",
                       (title, description, link, image, pin_id))
            db.commit()
            if image != old_image:
                remove_uploaded_image_if_unused(db, old_image)
            flash("Pin updated.", "success")
            return redirect(url_for("pin_detail", pin_id=pin_id))
        if upload and upload.filename and image:
            remove_uploaded_image_if_unused(db, image)
    return render_template("edit_pin.html", pin=pin)


@app.post("/pins/<int:pin_id>/delete")
@login_required
def delete_pin(pin_id):
    db = get_db()
    pin = db.execute(
        "SELECT id, image FROM pins WHERE id = ? AND user_id = ?",
        (pin_id, g.user["id"]),
    ).fetchone()
    if not pin:
        abort(404)

    image = pin["image"]
    db.execute("DELETE FROM pins WHERE id = ?", (pin_id,))
    db.commit()

    remove_uploaded_image_if_unused(db, image)

    flash("Pin deleted.", "success")
    return redirect(url_for("profile", username=g.user["username"]))


@app.post("/pins/<int:pin_id>/save")
@login_required
def save_pin(pin_id):
    board_id = request.form.get("board_id", type=int)
    db = get_db()
    board = db.execute("SELECT id FROM boards WHERE id=? AND user_id=?", (board_id, g.user["id"])).fetchone()
    pin = db.execute("SELECT id FROM pins WHERE id=?", (pin_id,)).fetchone()
    if not board or not pin:
        abort(404)
    existing = db.execute("SELECT 1 FROM saved_pins WHERE pin_id=? AND board_id=?", (pin_id, board_id)).fetchone()
    if existing:
        db.execute("DELETE FROM saved_pins WHERE pin_id=? AND board_id=?", (pin_id, board_id))
        message = "Pin removed from your board."
    else:
        db.execute("INSERT OR IGNORE INTO saved_pins(pin_id,board_id,created_at) VALUES(?,?,?)", (pin_id, board_id, timestamp()))
        message = "Pin saved to your board."
    db.commit()
    flash(message, "success")
    return redirect(url_for("pin_detail", pin_id=pin_id))


@app.post("/boards/<int:board_id>/pins/<int:pin_id>/remove")
@login_required
def remove_saved_pin(board_id, pin_id):
    db = get_db()
    board = db.execute("SELECT id FROM boards WHERE id=? AND user_id=?", (board_id, g.user["id"])).fetchone()
    if not board:
        abort(404)
    db.execute("DELETE FROM saved_pins WHERE board_id=? AND pin_id=?", (board_id, pin_id))
    db.commit()
    flash("Pin removed from this board.", "success")
    return redirect(url_for("board_detail", board_id=board_id))


@app.post("/pins/<int:pin_id>/like")
@login_required
def toggle_like(pin_id):
    db = get_db()
    if not db.execute("SELECT id FROM pins WHERE id=?", (pin_id,)).fetchone():
        abort(404)
    existing = db.execute("SELECT 1 FROM likes WHERE user_id=? AND pin_id=?", (g.user["id"], pin_id)).fetchone()
    if existing:
        db.execute("DELETE FROM likes WHERE user_id=? AND pin_id=?", (g.user["id"], pin_id))
    else:
        db.execute("INSERT OR IGNORE INTO likes(user_id,pin_id,created_at) VALUES(?,?,?)", (g.user["id"], pin_id, timestamp()))
    db.commit()
    return redirect(url_for("pin_detail", pin_id=pin_id))


@app.post("/pins/<int:pin_id>/comments")
@login_required
def add_comment(pin_id):
    db = get_db()
    if not db.execute("SELECT id FROM pins WHERE id=?", (pin_id,)).fetchone():
        abort(404)
    body = request.form.get("body", "").strip()[:2000]
    if body:
        db.execute("INSERT INTO comments(user_id,pin_id,body,created_at) VALUES(?,?,?,?)",
                   (g.user["id"], pin_id, body, timestamp()))
        db.commit()
    else:
        flash("Write a comment before posting.", "error")
    return redirect(url_for("pin_detail", pin_id=pin_id))


@app.post("/comments/<int:comment_id>/delete")
@login_required
def delete_comment(comment_id):
    db = get_db()
    comment = db.execute("SELECT c.*,p.user_id AS pin_owner FROM comments c JOIN pins p ON p.id=c.pin_id WHERE c.id=?", (comment_id,)).fetchone()
    if not comment:
        abort(404)
    if comment["user_id"] != g.user["id"] and comment["pin_owner"] != g.user["id"]:
        abort(403)
    db.execute("DELETE FROM comments WHERE id=?", (comment_id,))
    db.commit()
    flash("Comment deleted.", "success")
    return redirect(url_for("pin_detail", pin_id=comment["pin_id"]))


@app.route("/pins/<int:pin_id>/report", methods=["GET", "POST"])
@login_required
def report_pin(pin_id):
    db = get_db()
    pin = db.execute("SELECT id,title FROM pins WHERE id=?", (pin_id,)).fetchone()
    if not pin:
        abort(404)
    if request.method == "POST":
        reason = request.form.get("reason", "").strip()
        details = request.form.get("details", "").strip()[:1000]
        if reason not in {"spam", "harassment", "copyright", "other"}:
            flash("Choose a reason for your report.", "error")
        else:
            try:
                db.execute("INSERT INTO reports(reporter_id,pin_id,reason,details,created_at) VALUES(?,?,?,?,?)",
                           (g.user["id"], pin_id, reason, details, timestamp()))
                db.commit()
                flash("Thanks. Your report was sent for review.", "success")
            except sqlite3.IntegrityError:
                flash("You've already reported this pin.", "info")
            return redirect(url_for("pin_detail", pin_id=pin_id))
    return render_template("report.html", pin=pin)


def require_admin():
    configured_email = app.config["ADMIN_EMAIL"]
    if not g.user or not configured_email or g.user["email"].lower() != configured_email:
        abort(403)


@app.get("/admin/reports")
@login_required
def admin_reports():
    require_admin()
    reports = get_db().execute("""SELECT r.*,p.title,p.image,u.username AS reporter
      FROM reports r JOIN pins p ON p.id=r.pin_id JOIN users u ON u.id=r.reporter_id
      WHERE r.status='open' ORDER BY r.created_at ASC""").fetchall()
    return render_template("admin_reports.html", reports=reports)


@app.post("/admin/reports/<int:report_id>/dismiss")
@login_required
def dismiss_report(report_id):
    require_admin()
    db = get_db()
    db.execute("UPDATE reports SET status='reviewed' WHERE id=?", (report_id,))
    db.commit()
    flash("Report marked reviewed.", "success")
    return redirect(url_for("admin_reports"))


@app.post("/admin/reports/<int:report_id>/remove-pin")
@login_required
def remove_reported_pin(report_id):
    require_admin()
    db = get_db()
    report = db.execute("SELECT pin_id FROM reports WHERE id=?", (report_id,)).fetchone()
    if not report:
        abort(404)
    pin = db.execute("SELECT image FROM pins WHERE id=?", (report["pin_id"],)).fetchone()
    if pin:
        db.execute("DELETE FROM pins WHERE id=?", (report["pin_id"],))
        db.commit()
        remove_uploaded_image_if_unused(db, pin["image"])
    flash("Reported pin removed.", "success")
    return redirect(url_for("admin_reports"))


@app.route("/boards", methods=["GET", "POST"])
@login_required
def boards():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        description = request.form.get("description", "").strip()[:300]
        if name:
            db.execute("INSERT INTO boards(user_id,name,description,created_at) VALUES(?,?,?,?)", (g.user["id"], name, description, timestamp()))
            db.commit()
            flash("Board created.", "success")
            return redirect(url_for("boards"))
        flash("Give your board a name.", "error")
    items = db.execute("SELECT b.*,COUNT(s.pin_id) AS pin_count FROM boards b LEFT JOIN saved_pins s ON s.board_id=b.id WHERE b.user_id=? GROUP BY b.id ORDER BY b.created_at DESC", (g.user["id"],)).fetchall()
    return render_template("boards.html", boards=items)


@app.route("/boards/<int:board_id>")
@login_required
def board_detail(board_id):
    db = get_db()
    board = db.execute("SELECT * FROM boards WHERE id=? AND user_id=?", (board_id, g.user["id"])).fetchone()
    if not board:
        abort(404)
    pins = db.execute("SELECT p.*,u.username,(SELECT COUNT(*) FROM saved_pins x WHERE x.pin_id=p.id) AS saves FROM saved_pins s JOIN pins p ON p.id=s.pin_id JOIN users u ON u.id=p.user_id WHERE s.board_id=? ORDER BY s.created_at DESC", (board_id,)).fetchall()
    return render_template("board.html", board=board, pins=pins)


@app.post("/boards/<int:board_id>/delete")
@login_required
def delete_board(board_id):
    db = get_db()
    board = db.execute("SELECT id,name FROM boards WHERE id=? AND user_id=?", (board_id, g.user["id"])).fetchone()
    if not board:
        abort(404)
    if board["name"] == "Favorites":
        flash("The Favorites board can't be deleted.", "error")
    else:
        db.execute("DELETE FROM boards WHERE id=?", (board_id,))
        db.commit()
        flash("Board deleted.", "info")
    return redirect(url_for("boards"))


@app.route("/profile/<username>")
def profile(username):
    db = get_db()
    user = db.execute("""SELECT u.id,u.username,u.created_at,u.bio,u.avatar,
      (SELECT COUNT(*) FROM follows f WHERE f.followed_id=u.id) AS follower_count,
      (SELECT COUNT(*) FROM follows f WHERE f.follower_id=u.id) AS following_count
      FROM users u WHERE u.username=?""", (username,)).fetchone()
    if not user:
        abort(404)
    pins = db.execute("""SELECT p.*,u.username,
      (SELECT COUNT(*) FROM saved_pins s WHERE s.pin_id=p.id) AS saves,
      (SELECT COUNT(*) FROM likes l WHERE l.pin_id=p.id) AS likes,
      (SELECT COUNT(*) FROM comments c WHERE c.pin_id=p.id) AS comment_count
      FROM pins p JOIN users u ON u.id=p.user_id WHERE p.user_id=? ORDER BY p.created_at DESC""", (user["id"],)).fetchall()
    is_following = bool(g.user and db.execute("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?", (g.user["id"], user["id"])).fetchone())
    return render_template("profile.html", profile_user=user, pins=pins, is_following=is_following)


@app.post("/profile/<username>/follow")
@login_required
def toggle_follow(username):
    db = get_db()
    target = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if not target:
        abort(404)
    if target["id"] == g.user["id"]:
        flash("You can't follow your own profile.", "error")
    else:
        pair = (g.user["id"], target["id"])
        exists = db.execute("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?", pair).fetchone()
        if exists:
            db.execute("DELETE FROM follows WHERE follower_id=? AND followed_id=?", pair)
            flash("You unfollowed this creator.", "info")
        else:
            db.execute("INSERT INTO follows(follower_id,followed_id,created_at) VALUES(?,?,?)", (*pair, timestamp()))
            flash("You are now following this creator.", "success")
        db.commit()
    return redirect(url_for("profile", username=username))


@app.route("/following")
@login_required
def following_feed():
    db = get_db()
    pins = db.execute("""SELECT p.*,u.username,
      (SELECT COUNT(*) FROM saved_pins s WHERE s.pin_id=p.id) AS saves,
      (SELECT COUNT(*) FROM likes l WHERE l.pin_id=p.id) AS likes,
      (SELECT COUNT(*) FROM comments c WHERE c.pin_id=p.id) AS comment_count,
      EXISTS(SELECT 1 FROM likes mine WHERE mine.pin_id=p.id AND mine.user_id=?) AS liked
      FROM pins p JOIN users u ON u.id=p.user_id
      JOIN follows f ON f.followed_id=p.user_id WHERE f.follower_id=?
      ORDER BY p.created_at DESC""", (g.user["id"], g.user["id"])).fetchall()
    return render_template("following.html", pins=pins)


@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if request.method == "POST":
        bio = request.form.get("bio", "").strip()[:280]
        avatar = request.form.get("avatar", "").strip()[:500]
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if avatar and not avatar.startswith(("https://", "http://")):
            flash("Profile photo links must start with http:// or https://.", "error")
        elif current_password or new_password or confirm_password:
            account = get_db().execute("SELECT password FROM users WHERE id=?", (g.user["id"],)).fetchone()
            if not check_password_hash(account["password"], current_password):
                flash("Your current password didn't match.", "error")
            elif len(new_password) < 10 or len(new_password) > 128:
                flash("Choose a new password between 10 and 128 characters.", "error")
            elif new_password != confirm_password:
                flash("The new passwords do not match.", "error")
            else:
                db = get_db()
                db.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(new_password), g.user["id"]))
                db.execute("UPDATE users SET bio=?,avatar=? WHERE id=?", (bio, avatar, g.user["id"]))
                db.commit()
                flash("Your profile and password have been updated.", "success")
                return redirect(url_for("profile", username=g.user["username"]))
        else:
            get_db().execute("UPDATE users SET bio=?,avatar=? WHERE id=?", (bio, avatar, g.user["id"]))
            get_db().commit()
            flash("Your profile has been updated.", "success")
            return redirect(url_for("profile", username=g.user["username"]))
    return render_template("settings.html", user=g.user)


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="We couldn't find that page."), 404


@app.errorhandler(400)
def bad_request(error):
    return render_template("error.html", code=400, message=getattr(error, "description", "That request could not be completed.")), 400


@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You don't have permission to do that."), 403


@app.errorhandler(413)
def upload_too_large(_error):
    return render_template("error.html", code=413, message="That upload is too large. Please choose a smaller image."), 413


@app.errorhandler(500)
def internal_error(error):
    app.logger.exception("Unhandled Eclipse server error", exc_info=error)
    return render_template("error.html", code=500, message="Something went wrong. Please try again."), 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
