import os
import secrets
import sqlite3
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

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
)
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


@app.get("/uploads/<path:filename>")
def uploaded_image(filename):
    return send_from_directory(UPLOAD_DIR, filename)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
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
      email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at TEXT NOT NULL
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
    CREATE INDEX IF NOT EXISTS pins_created ON pins(created_at DESC);
    """)
    db.commit()


@app.before_request
def prepare_request():
    init_db()
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(24)
    g.user = None
    if session.get("user_id"):
        g.user = get_db().execute("SELECT id, username, email FROM users WHERE id = ?", (session["user_id"],)).fetchone()


@app.context_processor
def template_context():
    return {"current_user": getattr(g, "user", None), "csrf_token": session.get("csrf_token", "")}


@app.before_request
def csrf_protect():
    if request.method == "POST" and request.form.get("csrf_token") != session.get("csrf_token"):
        abort(400, "The form expired. Please refresh and try again.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please sign in to do that.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def timestamp():
    return datetime.utcnow().isoformat(timespec="seconds")


def fetch_pins(query=""):
    db = get_db()
    sql = "SELECT p.*, u.username, (SELECT COUNT(*) FROM saved_pins s WHERE s.pin_id=p.id) AS saves FROM pins p JOIN users u ON u.id=p.user_id"
    params = []
    if query:
        sql += " WHERE p.title LIKE ? OR p.description LIKE ? OR u.username LIKE ?"
        params = [f"%{query}%"] * 3
    sql += " ORDER BY p.created_at DESC"
    return db.execute(sql, params).fetchall()


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
        elif len(password) < 8:
            flash("Your password must be at least 8 characters.", "error")
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
        if user and check_password_hash(user["password"], request.form.get("password", "")):
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
            filename = secure_filename(upload.filename)
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in ALLOWED_EXTENSIONS:
                flash("Upload a PNG, JPG, GIF, or WebP image.", "error")
            else:
                filename = f"{secrets.token_hex(12)}.{ext}"
                upload.save(UPLOAD_DIR / filename)
                image = url_for("uploaded_image", filename=filename)
        elif image_url.startswith(("https://", "http://")):
            image = image_url
        elif image_url:
            flash("Image links need to start with http:// or https://.", "error")
        if not title:
            flash("Add a title for your pin.", "error")
        elif not image:
            if not (upload and upload.filename and ext not in ALLOWED_EXTENSIONS):
                flash("Choose an image to upload or add an image URL.", "error")
        else:
            if link and not link.startswith(("https://", "http://")):
                link = "https://" + link
            cur = get_db().execute("INSERT INTO pins(user_id,title,description,image,link,created_at) VALUES(?,?,?,?,?,?)",
                                   (g.user["id"], title, description, image, link, timestamp()))
            get_db().commit()
            flash("Your pin is live!", "success")
            return redirect(url_for("pin_detail", pin_id=cur.lastrowid))
    return render_template("create.html")


@app.route("/pins/<int:pin_id>")
def pin_detail(pin_id):
    pin = get_db().execute("SELECT p.*,u.username FROM pins p JOIN users u ON u.id=p.user_id WHERE p.id=?", (pin_id,)).fetchone()
    if not pin:
        abort(404)
    boards = []
    saved = False
    if g.user:
        boards = get_db().execute("SELECT * FROM boards WHERE user_id=? ORDER BY name", (g.user["id"],)).fetchall()
        saved = get_db().execute("SELECT 1 FROM saved_pins s JOIN boards b ON b.id=s.board_id WHERE s.pin_id=? AND b.user_id=?", (pin_id, g.user["id"])).fetchone() is not None
    return render_template("pin.html", pin=pin, boards=boards, saved=saved)


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

    upload_prefixes = (
        "/uploads/",
        url_for("static", filename="uploads/"),
    )
    upload_prefix = next((prefix for prefix in upload_prefixes if image.startswith(prefix)), None)
    if upload_prefix:
        filename = Path(image).name
        image_path = UPLOAD_DIR / filename
        still_used = db.execute(
            "SELECT 1 FROM pins WHERE image = ? LIMIT 1", (image,)
        ).fetchone()
        if not still_used and image_path.parent == UPLOAD_DIR and image_path.is_file():
            image_path.unlink()

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
    db.execute("INSERT OR IGNORE INTO saved_pins(pin_id,board_id,created_at) VALUES(?,?,?)", (pin_id, board_id, timestamp()))
    db.commit()
    flash("Saved to your board.", "success")
    return redirect(url_for("pin_detail", pin_id=pin_id))


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
    user = get_db().execute("SELECT id,username,created_at FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        abort(404)
    pins = get_db().execute("SELECT p.*,u.username,(SELECT COUNT(*) FROM saved_pins s WHERE s.pin_id=p.id) AS saves FROM pins p JOIN users u ON u.id=p.user_id WHERE p.user_id=? ORDER BY p.created_at DESC", (user["id"],)).fetchall()
    return render_template("profile.html", profile_user=user, pins=pins)


@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="We couldn't find that page."), 404


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
