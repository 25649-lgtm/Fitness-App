import os
import math
import secrets
import sqlite3
import tempfile
from datetime import date as calendar_date, timedelta
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash

from flask import (
    Flask,
    abort,
    g,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def database_path():
    """优先使用配置路径；默认将数据库放在 instance，避免虚拟环境重建丢数据。"""
    configured = os.environ.get("GYMTRACKER_DATABASE")
    if configured:
        target = os.path.abspath(configured)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        return target
    target = os.path.join(BASE_DIR, "instance", "database.db")
    legacy = os.path.join(BASE_DIR, ".venv", "database.db")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    if os.path.exists(target) or not os.path.exists(legacy):
        return target
    # SQLite backup 能复制一致快照，包括 WAL 内容；原数据库作为备份保留。
    handle, temporary = tempfile.mkstemp(
        dir=os.path.dirname(target), suffix=".db"
    )
    os.close(handle)
    try:
        with closing(sqlite3.connect(legacy)) as source:
            with closing(sqlite3.connect(temporary)) as destination:
                source.backup(destination)
                if (
                    destination.execute("PRAGMA integrity_check").fetchone()[0]
                    != "ok"
                ):
                    raise RuntimeError(
                        "Database migration integrity check failed"
                    )
        # 完整备份完成后才发布目标文件，已有目标绝不覆盖，支持重复启动。
        try:
            os.link(temporary, target)
        except FileExistsError:
            pass
    finally:
        os.remove(temporary)
    return target


DATABASE = database_path()


# 初始化应用；优先读取环境密钥，本地开发则使用持久化的随机密钥文件。
app = Flask(__name__)


def load_secret_key():
    """让密钥保持私密且重启后稳定，避免使用代码中公开的固定值。"""
    configured = os.environ.get("GYMTRACKER_SECRET_KEY")
    if configured:
        if len(configured) < 32:
            raise ValueError(
                "GYMTRACKER_SECRET_KEY must contain at least 32 characters"
            )
        return configured
    os.makedirs(app.instance_path, exist_ok=True)
    key_path = os.path.join(app.instance_path, "secret_key")
    try:
        # 独占创建，已有文件绝不覆盖；密钥文件必须排除在版本控制之外。
        descriptor = os.open(
            key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
        )
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as key_file:
            key_file.write(secrets.token_hex(32))
    with open(key_path, encoding="utf-8") as key_file:
        key = key_file.read().strip()
    if len(key) < 32:
        raise ValueError("Local session key is invalid")
    return key


app.config.update(
    SECRET_KEY=load_secret_key(),
    # 关闭调试模式后仍检查模板更新，避免保存 HTML 后页面继续使用旧链接。
    TEMPLATES_AUTO_RELOAD=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def csrf_token():
    """为当前会话生成随机表单令牌，同一会话中的多个页面可以共用。"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_form_submission():
    """在写操作进入路由前验证令牌，拒绝缺失、伪造及其他会话的提交。"""
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        expected = session.get("csrf_token", "")
        supplied = request.form.get("csrf_token", "")
        # 使用字节比较，既避免时序泄露，也让非 ASCII 错误输入正常返回 400。
        if not expected or not secrets.compare_digest(
            expected.encode("utf-8"), supplied.encode("utf-8")
        ):
            abort(
                400,
                description="Form expired or invalid. Reload the pa"
                "ge and try again.",
            )


@app.after_request
def preserve_redirect_messages(response):
    """异步计划表单不提前跟随跳转，确保成功提示只在真正打开目标页时消费。"""
    if request.headers.get(
        "X-Plan-Navigation"
    ) == "1" and response.status_code in (302, 303):
        response.headers["X-Redirect-To"] = response.headers.pop("Location")
        response.status_code = 200
    return response


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def friendly_error(error):
    """统一错误页面，不向用户暴露异常、SQL 或服务器路径。"""
    messages = {
        400: (
            "Unable to submit",
            "This request is invalid or the form ha"
            "s expired. Return to the page, reload "
            "it and try again.",
        ),
        404: (
            "Page not found",
            "This page or record does not exist, or"
            " is not available to your account.",
        ),
        500: (
            "Something went wrong",
            "We could not complete your request. Please try again later.",
        ),
    }
    title, message = messages[error.code]
    return (
        render_template(
            "error.html", code=error.code, title=title, message=message
        ),
        error.code,
    )


def init_db():
    # 创建这个健身应用需要的数据库表
    # conn 管理事务，closing 确保关闭连接，避免 Windows 下数据库文件被锁住。
    with closing(sqlite3.connect(DATABASE)) as conn, conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS User (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                weight REAL,
                height REAL,
                goal TEXT
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS WorkPlan (
                plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_name TEXT NOT NULL,
                description TEXT,
                date TEXT,
                FOREIGN KEY (user_id) REFERENCES User(user_id)
            )
            """)
        # 用独立字段记录密码是否已哈希，避免根据密码内容误判存储格式。
        columns = {row[1] for row in conn.execute("PRAGMA table_info(User)")}
        if "password_hashed" not in columns:
            # 兼容旧数据库：新增标记，原有账户默认尚未转换。
            conn.execute(
                "ALTER TABLE User ADD COLUMN password_hashed INTEGER "
                "NOT NULL DEFAULT 0"
            )
        # 只迁移未转换的账户；密码和标记一起更新，重复启动不会重复哈希。
        for user_id, password in conn.execute(
            "SELECT user_id, password FROM User WHERE password_hashed = 0"
        ).fetchall():
            conn.execute(
                "UPDATE User SET password = ?, password_hashed = 1 "
                "WHERE user_id = ?",
                (generate_password_hash(password), user_id),
            )
        conn.execute("""
            CREATE TABLE IF NOT EXISTS WorkDay (
                day_id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER NOT NULL,
                day_name TEXT NOT NULL,
                FOREIGN KEY (plan_id) REFERENCES WorkPlan(plan_id)
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS Exercise (
                exercise_id INTEGER PRIMARY KEY AUTOINCREMENT,
                exercise_name TEXT NOT NULL,
                description TEXT,
                equipment TEXT
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS WorkoutExercise (
                workout_exercise_id INTEGER PRIMARY KEY AUTOINCREMENT,
                day_id INTEGER NOT NULL,
                exercise_id INTEGER NOT NULL,
                sets INTEGER,
                reps INTEGER,
                FOREIGN KEY (day_id) REFERENCES WorkDay(day_id),
                FOREIGN KEY (exercise_id) REFERENCES Exercise(exercise_id)
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS WorkNotes (
                notes_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                exercise_id INTEGER NOT NULL,
                date TEXT,
                weight REAL,
                sets INTEGER,
                reps INTEGER,
                notes TEXT,
                FOREIGN KEY (user_id) REFERENCES User(user_id),
                FOREIGN KEY (exercise_id) REFERENCES Exercise(exercise_id)
            )
            """)
        # 无创建者的旧动作继续作为公共基础动作，新动作关联创建账户。
        exercise_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(Exercise)")
        }
        if "user_id" not in exercise_columns:
            conn.execute(
                "ALTER TABLE Exercise ADD COLUMN user_id INTEGER "
                "REFERENCES User(user_id)"
            )
        # 记录来源计划动作；旧记录保留为空，删除计划时保留训练历史。
        note_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(WorkNotes)")
        }
        if "workout_exercise_id" not in note_columns:
            conn.execute(
                "ALTER TABLE WorkNotes ADD COLUMN workout_exercise_id "
                "INTEGER REFERENCES WorkoutExercise(workout_exercise_id) "
                "ON DELETE SET NULL"
            )
        # 动作表为空时加入一些基础动作
        if conn.execute("SELECT COUNT(*) FROM Exercise").fetchone()[0] == 0:
            conn.executemany(
                """
                INSERT INTO Exercise (
                    exercise_name,
                    description,
                    equipment
                )
                VALUES (?, ?, ?);
                """,
                [
                    ("Bench Press", "Chest pressing movement", "Barbell"),
                    ("Squat", "Compound lower-body movement", "Barbell"),
                    ("Deadlift", "Compound hip-hinge movement", "Barbell"),
                    ("Lat Pulldown", "Vertical back pull", "Cable machine"),
                    (
                        "Shoulder Press",
                        "Overhead pressing movement",
                        "Dumbbells",
                    ),
                    ("Plank", "Core stability hold", "Bodyweight"),
                ],
            )
        conn.commit()


init_db()


def get_db():
    db = getattr(g, "_database", None)

    if db is None:
        db = g._database = sqlite3.connect(DATABASE)

        # Allow columns to be accessed by name
        db.row_factory = sqlite3.Row

        # Enable foreign keys
        db.execute("PRAGMA foreign_keys = ON")

    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)

    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cursor = get_db().execute(query, args)
    results = cursor.fetchall()
    cursor.close()

    if one:
        return results[0] if results else None

    return results


@app.route("/register", methods=["GET", "POST"])
@app.route("/signup", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        user_name = request.form.get("user_name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 创建账户前检查表单内容
        if not user_name or not email or not password:
            error = "Please fill in all fields."
        elif len(password) < 8:
            error = "Password must contain at least 8 characters."
        elif password != confirm_password:
            error = "Passwords do not match."
        else:
            existing_user = query_db(
                "SELECT user_id FROM User WHERE email = ?;",
                (email,),
                one=True,
            )

            if existing_user is not None:
                error = "An account with that email already exists."
            else:
                db = get_db()
                # 注册时只保存带随机盐的密码哈希，并标记为已转换。
                db.execute(
                    """
                    INSERT INTO User (
                        user_name, email, password, password_hashed
                    )
                    VALUES (?, ?, ?, 1);
                    """,
                    (user_name, email, generate_password_hash(password)),
                )
                db.commit()
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("sign up.html", error=error)


@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if "user_id" in session:
        return redirect(url_for("homepage"))
    if request.method == "POST":
        # 保留邮箱大小写；只清理首尾空格，缺失字段使用空字符串。
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # 按邮箱查询账户；密码由下面的哈希验证函数检查。
        user_sql = """
            SELECT user_id, user_name, email, password
            FROM User
            WHERE email = ?;
        """
        user = query_db(user_sql, (email,), one=True)

        # 哈希不能直接与输入密码比较，需要使用 check_password_hash 验证。
        if user is None:
            error = "Incorrect email"
        elif not check_password_hash(user["password"], password):
            error = "Incorrect password"
        else:
            # 登录成功后先清除旧会话，再保存当前账户信息。
            session.clear()
            session["user_id"] = user["user_id"]
            session["user_name"] = user["user_name"]
            session["email"] = user["email"]
            return redirect(url_for("homepage"))
    return render_template("login.html", error=error)


def today_date():
    """使用运行电脑的本地日期，测试时可固定日期验证跨周边界。"""
    return calendar_date.today()


@app.route("/homepage")
def homepage():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]

    user_sql = """
        SELECT user_id, user_name, weight, height, goal
        FROM User
        WHERE user_id = ?;
    """
    user = query_db(user_sql, (user_id,), one=True)

    # 周一到下周一采用左闭右开范围；今日动作还需满足计划已开始。
    today = today_date()
    week_start = today - timedelta(days=today.weekday())
    week_end = week_start + timedelta(days=7)
    # 按数字星期索引匹配，避免系统语言影响英文训练日名称。
    weekday = TRAINING_DAYS[today.weekday()]
    # 日期去掉连字符后比较，同时兼容旧版 YYYYMMDD 数据。
    # 查找当前用户今天安排的动作
    workout_sql = """
        SELECT
            WorkoutExercise.workout_exercise_id,
            WorkPlan.plan_name,
            WorkDay.day_name,
            Exercise.exercise_name,
            Exercise.equipment,
            WorkoutExercise.sets,
            WorkoutExercise.reps,
            EXISTS (
                SELECT 1 FROM WorkNotes n
                WHERE n.workout_exercise_id =
                    WorkoutExercise.workout_exercise_id
                AND n.user_id = WorkPlan.user_id
                AND REPLACE(n.date, '-', '') = ?
            ) AS completed
        FROM WorkoutExercise
        JOIN WorkDay
            ON WorkoutExercise.day_id = WorkDay.day_id
        JOIN WorkPlan
            ON WorkDay.plan_id = WorkPlan.plan_id
        JOIN Exercise
            ON WorkoutExercise.exercise_id = Exercise.exercise_id
        WHERE WorkPlan.user_id = ? AND WorkDay.day_name = ?
        AND REPLACE(WorkPlan.date, '-', '') <= ?
        ORDER BY WorkPlan.plan_id, WorkDay.day_id,
                 WorkoutExercise.workout_exercise_id;
    """
    workouts = query_db(
        workout_sql,
        (today.strftime("%Y%m%d"), user_id, weekday, today.strftime("%Y%m%d")),
    )

    # 一次查询本周可能生效的安排，空训练日也保留，避免误当成休息日。
    planned = query_db(
        "SELECT p.plan_id, p.plan_name, p.date, d.day_name, "
        "e.exercise_name, we.sets, we.reps "
        "FROM WorkPlan p JOIN WorkDay d ON d.plan_id = p.plan_id "
        "LEFT JOIN WorkoutExercise we ON we.day_id = d.day_id "
        "LEFT JOIN Exercise e ON e.exercise_id = we.exercise_id "
        "WHERE p.user_id = ? AND REPLACE(p.date, '-', '') < ? "
        "ORDER BY p.plan_id, d.day_id, we.workout_exercise_id",
        (user_id, week_end.strftime("%Y%m%d")),
    )
    weekly_plan = []
    for offset, day_name in enumerate(TRAINING_DAYS):
        day_date = week_start + timedelta(days=offset)
        # 计划开始日前的星期安排不显示，兼容旧版无连字符的日期。
        entries = [
            row
            for row in planned
            if row["day_name"] == day_name
            and str(row["date"]).replace("-", "")
            <= day_date.strftime("%Y%m%d")
        ]
        weekly_plan.append(
            {
                "name": day_name,
                "date": day_date,
                "entries": entries,
            }
        )

    notes_sql = """
        SELECT
            Exercise.exercise_name,
            WorkNotes.date,
            WorkNotes.weight,
            WorkNotes.sets,
            WorkNotes.reps,
            WorkNotes.notes
        FROM WorkNotes
        JOIN Exercise
            ON WorkNotes.exercise_id = Exercise.exercise_id
        WHERE WorkNotes.user_id = ?
        ORDER BY WorkNotes.date DESC
        LIMIT 5;
    """
    recent_notes = query_db(notes_sql, (user_id,))

    # 只统计本周训练记录；每条动作记录计为一条，不当作整次训练。
    stats_sql = """
        SELECT
            COUNT(*) AS workout_count,
            COUNT(DISTINCT exercise_id) AS exercise_count
        FROM WorkNotes
        WHERE user_id = ?
        AND REPLACE(date, '-', '') >= ? AND REPLACE(date, '-', '') < ?;
    """
    stats = query_db(
        stats_sql,
        (user_id, week_start.strftime("%Y%m%d"), week_end.strftime("%Y%m%d")),
        one=True,
    )

    return render_template(
        "homepage.html",
        user=user,
        workouts=workouts,
        weekly_plan=weekly_plan,
        recent_notes=recent_notes,
        stats=stats,
        today=today,
        week_start=week_start,
        week_last=week_end - timedelta(days=1),
    )


@app.route("/logout", methods=["POST"])
def logout():
    # 退出会改变登录状态，因此只允许通过带有效 CSRF 令牌的表单提交。
    session.clear()
    return redirect(url_for("login"))


@app.route("/training/<int:id>", methods=["GET", "POST"])
def training(id):
    # 训练详情属于私人数据，未登录用户先返回登录页。
    if "user_id" not in session:
        return redirect(url_for("login"))
    # 同时按动作记录 ID 和当前用户筛选，防止修改网址后查看他人的训练。
    sql = """
        SELECT
            WorkoutExercise.workout_exercise_id,
            Exercise.exercise_id,
            User.user_name,
            WorkPlan.plan_name,
            WorkPlan.description AS plan_description,
            WorkPlan.date,
            WorkDay.day_name,
            Exercise.exercise_name,
            Exercise.description AS exercise_description,
            Exercise.equipment,
            WorkoutExercise.sets,
            WorkoutExercise.reps
        FROM WorkoutExercise
        JOIN WorkDay
            ON WorkoutExercise.day_id = WorkDay.day_id
        JOIN WorkPlan
            ON WorkDay.plan_id = WorkPlan.plan_id
        JOIN User
            ON WorkPlan.user_id = User.user_id
        JOIN Exercise
            ON WorkoutExercise.exercise_id = Exercise.exercise_id
        WHERE WorkoutExercise.workout_exercise_id = ?
        AND WorkPlan.user_id = ?;
    """

    result = query_db(sql, (id, session["user_id"]), one=True)

    # 不存在或不属于当前用户时统一返回 404，不透露他人的记录是否存在。
    if result is None:
        abort(404)

    # 从计划动作预填训练结果，实际完成的重量和次数仍由用户确认。
    error = None
    if request.method == "POST":
        values, error = validate_note_form()
        if not error and values[0] != result["exercise_id"]:
            error = "Record the exercise shown in this workout."
        if not error:
            db = get_db()
            with db:
                db.execute(
                    "INSERT INTO WorkNotes (exercise_id, da"
                    "te, weight, sets, reps, notes, user_id, "
                    "workout_exercise_id"
                    ") "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (*values, session["user_id"], id),
                )
            # 从计划开始的训练保存后返回主页，直接查看对应动作的完成状态。
            flash("Workout recorded.", "success")
            return redirect(url_for("homepage"))
    defaults = {
        "exercise_id": result["exercise_id"],
        "date": today_date().isoformat(),
        "sets": result["sets"],
        "reps": result["reps"],
        "weight": "",
        "notes": "",
    }
    return render_template(
        "training.html",
        training=result,
        note=defaults,
        exercises=[result],
        error=error,
    ), (400 if error else 200)


def available_exercises():
    """统一列出公共动作和当前用户的自定义动作，供所有选择表单使用。"""
    return query_db(
        "SELECT exercise_id, exercise_name, description, equipment, user_id "
        "FROM Exercise WHERE user_id IS NULL OR user_id = ? "
        "ORDER BY exercise_name",
        (session.get("user_id"),),
    )


def available_exercise(exercise_id):
    """服务端验证动作权限，防止伪造表单引用其他账户的私人动作。"""
    return query_db(
        "SELECT exercise_id FROM Exercise WHERE exercise_id = ? "
        "AND (user_id IS NULL OR user_id = ?)",
        (exercise_id, session.get("user_id")),
        one=True,
    )


@app.route("/exercises")
def exercises():
    """动作库只展示可用动作与新增入口。"""
    return render_template("exercises.html", exercises=available_exercises())


@app.route("/exercises/new", methods=["GET", "POST"])
def create_exercise():
    """独立页面创建私人动作，保存成功后返回动作库。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        name = request.form.get("exercise_name", "").strip()
        equipment = request.form.get("equipment", "").strip()
        description = request.form.get("description", "").strip()
        if not name or len(name) > 120:
            error = "Enter an exercise name between 1 and 120 characters."
        elif len(equipment) > 120 or len(description) > 2000:
            error = (
                "Keep equipment within 120 and description "
                "within 2000 characters."
            )
        elif any(
            row["exercise_name"].casefold() == name.casefold()
            for row in available_exercises()
        ):
            error = "An exercise with this name is already available."
        else:
            # 参数化写入并绑定登录账户，创建成功后刷新动作列表。
            db = get_db()
            with db:
                db.execute(
                    "INSERT INTO Exercise "
                    "(exercise_name, description, equipment, user_id) "
                    "VALUES (?, ?, ?, ?)",
                    (name, description, equipment, session["user_id"]),
                )
            flash("Exercise created.", "success")
            return redirect(url_for("exercises"))
    return render_template("create exercise.html", error=error), (
        400 if error else 200
    )


def validate_note_form():
    """验证动作、真实日期、有限非负重量及正整数组数次数。"""
    exercise_id = request.form.get("exercise_id", "")
    date_text = request.form.get("date", "").strip()
    weight_text = request.form.get("weight", "").strip()
    note_text = request.form.get("notes", "").strip()
    exercise = available_exercise(exercise_id)
    if exercise is None:
        return None, "Select a valid exercise."
    try:
        if calendar_date.fromisoformat(date_text).isoformat() != date_text:
            raise ValueError
    except ValueError:
        return None, "Enter a valid date (YYYY-MM-DD)."
    try:
        # 重量可以留空；不能将错误数字静默转换为空值，也不能接受 NaN 或无穷大。
        weight = float(weight_text) if weight_text else None
        if weight is not None and (not math.isfinite(weight) or weight < 0):
            raise ValueError
    except (ValueError, OverflowError):
        return (
            None,
            "Weight must be a finite number of 0 or more, or left blank.",
        )
    sets, reps = positive_count("sets"), positive_count("reps")
    if sets is None or reps is None:
        return (
            None,
            "Sets and reps must be whole numbers from 1 to 2147483647.",
        )
    if len(note_text) > 2000:
        return None, "Keep notes within 2000 characters."
    return (
        exercise["exercise_id"],
        date_text,
        weight,
        sets,
        reps,
        note_text,
    ), None


def owned_note(note_id):
    """按当前账户筛选记录，未知 ID 和他人记录统一返回 404。"""
    note = query_db(
        "SELECT notes_id, exercise_id, date, weight, sets, reps, notes "
        "FROM WorkNotes WHERE notes_id = ? AND user_id = ?",
        (note_id, session["user_id"]),
        one=True,
    )
    if note is None:
        abort(404)
    return note


@app.route("/notes/<int:note_id>/edit", methods=["GET", "POST"])
def edit_note(note_id):
    """更新本人记录，验证失败时保留表单输入，不写入数据库。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    note = owned_note(note_id)
    error = None
    if request.method == "POST":
        values, error = validate_note_form()
        if not error:
            db = get_db()
            with db:
                db.execute(
                    "UPDATE WorkNotes SET exercise_id = ?, "
                    "date = ?, weight = ?, "
                    "sets = ?, reps = ?, notes = ? WHERE no"
                    "tes_id = ? AND user_id = ?",
                    (*values, note_id, session["user_id"]),
                )
            # 保存成功后提供明确反馈。
            flash("Workout record updated.", "success")
            return redirect(url_for("notes"))
    # 编辑记录时也只提供公共动作和当前账户的私人动作。
    exercises = available_exercises()
    return render_template(
        # 训练与编辑记录共用结果页面，未传 training 时显示编辑模式。
        "training.html",
        note=note,
        exercises=exercises,
        error=error,
    ), (400 if error else 200)


@app.route("/notes/<int:note_id>/delete", methods=["GET", "POST"])
def delete_note(note_id):
    """GET 显示记录摘要；只有带确认值和 CSRF 令牌的 POST 才删除本人记录。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    note = owned_note(note_id)
    if request.method == "POST":
        if request.form.get("confirm") != "yes":
            abort(400, description="Please confirm deletion.")
        db = get_db()
        with db:
            db.execute(
                "DELETE FROM WorkNotes WHERE notes_id = ? AND user_id = ?",
                (note_id, session["user_id"]),
            )
        # 保存成功后提供明确反馈。
        flash("Workout record deleted.", "success")
        return redirect(url_for("notes"))
    exercise = query_db(
        "SELECT exercise_name FROM Exercise WHERE exercise_id = ?",
        (note["exercise_id"],),
        one=True,
    )
    # 三种删除操作共用确认页，保留各自不同的删除影响说明。
    return render_template(
        "confirm deletion.html",
        title="Delete Workout Record",
        item_name=exercise["exercise_name"],
        summary=f"{note['date']} · {note['sets']} × {note['reps']}",
        message=(
            "This permanently deletes this workout record. "
            "Your workout plans are not affected."
        ),
        cancel_url=url_for("notes"),
        plan_navigation=False,
    )


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))

    error = None

    # 添加与编辑使用相同的服务端校验，防止绕过 HTML 限制写入无效数据。
    if request.method == "POST":
        values, error = validate_note_form()
        if not error:
            db = get_db()
            with db:
                db.execute(
                    "INSERT INTO WorkNotes (exercise_id, da"
                    "te, weight, sets, reps, notes, user_id"
                    ") "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (*values, session["user_id"]),
                )
            # 保存成功后提供明确反馈。
            flash("Workout recorded.", "success")
            return redirect(url_for("notes"))

    filters = {
        key: request.args.get(key, "").strip()
        for key in ("exercise_id", "date_from", "date_to")
    }
    filter_error = None
    conditions = ["WorkNotes.user_id = ?"]
    arguments = [session["user_id"]]
    if filters["exercise_id"]:
        selected = available_exercise(filters["exercise_id"])
        if selected is None:
            filter_error = "Select a valid exercise filter."
        else:
            conditions.append("WorkNotes.exercise_id = ?")
            arguments.append(selected["exercise_id"])
    for key, operator in (("date_from", ">="), ("date_to", "<=")):
        value = filters[key]
        if value:
            try:
                parsed = calendar_date.fromisoformat(value)
                if parsed.isoformat() != value:
                    raise ValueError
                conditions.append(
                    f"REPLACE(WorkNotes.date, '-', '') {operator} ?"
                )
                arguments.append(parsed.strftime("%Y%m%d"))
            except ValueError:
                filter_error = "Enter valid filter dates (YYYY-MM-DD)."
    if (
        not filter_error
        and filters["date_from"]
        and filters["date_to"]
        and filters["date_from"] > filters["date_to"]
    ):
        filter_error = "The start date must not be after the end date."
    sql = (
        "SELECT WorkNotes.notes_id, Exercise.exercise_name, WorkNotes.date, "
        "WorkNotes.weight, WorkNotes.sets, WorkNotes.reps, WorkNotes.notes "
        "FROM WorkNotes JOIN Exercise ON WorkNo"
        "tes.exercise_id = Exercise.exercise_id"
        " "
        "WHERE "
        + " AND ".join(conditions)
        + " ORDER BY REPLACE(WorkNotes.date, '-',"
        " '') DESC, WorkNotes.notes_id DESC"
    )
    results = [] if filter_error else query_db(sql, tuple(arguments))
    exercise_options = available_exercises()

    return render_template(
        "work note.html",
        notes=results,
        filters=filters,
        filter_error=filter_error,
        exercises=exercise_options,
        error=error,
    ), (400 if error or filter_error else 200)


@app.route("/plans")
def plans():
    if "user_id" not in session:
        return redirect(url_for("login"))

    # 使用 LEFT JOIN，让没有动作的计划也能显示
    results = query_db(
        """
        SELECT
            WorkPlan.plan_id,
            WorkPlan.plan_name,
            WorkPlan.description,
            WorkPlan.date,
            COUNT(DISTINCT WorkDay.day_id) AS day_count,
            COUNT(WorkoutExercise.workout_exercise_id) AS exercise_count
        FROM WorkPlan
        LEFT JOIN WorkDay
            ON WorkDay.plan_id = WorkPlan.plan_id
        LEFT JOIN WorkoutExercise
            ON WorkoutExercise.day_id = WorkDay.day_id
        WHERE WorkPlan.user_id = ?
        GROUP BY WorkPlan.plan_id
        ORDER BY WorkPlan.plan_id DESC;
        """,
        (session["user_id"],),
    )

    return render_template("plans.html", plans=results)


@app.route("/profile", methods=["GET", "POST"])
def profile():
    """个人资料先校验再保存；失败时保留输入，不修改数据库或会话。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    user = query_db(
        "SELECT user_name, email, weight, heigh"
        "t, goal FROM User WHERE user_id = ?",
        (session["user_id"],),
        one=True,
    )
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        name = request.form.get("user_name", "").strip()
        goal = request.form.get("goal", "").strip()
        measurements = {}
        if not name or len(name) > 120:
            error = "Enter a name of 1 to 120 characters."
        elif len(goal) > 2000:
            error = "Keep your goal within 2000 characters."
        # 身高体重仍可留空；填写时必须是有限正数，拒绝 NaN 和无穷大。
        for field, label in (("weight", "Weight"), ("height", "Height")):
            raw = request.form.get(field, "").strip()
            try:
                value = float(raw) if raw else None
                if value is not None and (
                    not math.isfinite(value) or value <= 0
                ):
                    raise ValueError
                measurements[field] = value
            except (ValueError, OverflowError):
                if not error:
                    error = (
                        f"{label} must be a positive, finite number "
                        "or left blank."
                    )
        if not error:
            db = get_db()
            with db:
                db.execute(
                    "UPDATE User SET user_name = ?, weight "
                    "= ?, height = ?, goal = ? "
                    "WHERE user_id = ?",
                    (
                        name,
                        measurements["weight"],
                        measurements["height"],
                        goal,
                        session["user_id"],
                    ),
                )
            session["user_name"] = name
            # 保存成功后提供明确反馈。
            flash("Profile saved.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", user=user, error=error), (
        400 if error else 200
    )


# 训练日统一使用固定值，防止伪造表单写入任意名称。
TRAINING_DAYS = (
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
    "Sunday",
)


def owned_plan(plan_id):
    """只查询当前用户的计划，不存在或属于他人时统一返回 404。"""
    plan = query_db(
        "SELECT plan_id, plan_name, description, date FROM WorkPlan "
        "WHERE plan_id = ? AND user_id = ?",
        (plan_id, session["user_id"]),
        one=True,
    )
    if plan is None:
        abort(404)
    return plan


def validate_plan_form():
    """创建和编辑共用校验，错误时保留用户输入供页面重新显示。"""
    values = {
        key: request.form.get(key, "").strip()
        for key in ("plan_name", "description", "date")
    }
    days = list(dict.fromkeys(request.form.getlist("training_days")))
    error = None
    if not values["plan_name"] or len(values["plan_name"]) > 120:
        error = "Enter a plan name of 1 to 120 characters."
    elif len(values["description"]) > 2000:
        error = "Keep the description within 2000 characters."
    else:
        try:
            parsed = calendar_date.fromisoformat(values["date"])
            if parsed.isoformat() != values["date"]:
                raise ValueError
        except ValueError:
            error = "Enter a valid start date (YYYY-MM-DD)."
    if not error and (
        not days or any(day not in TRAINING_DAYS for day in days)
    ):
        error = "Select at least one valid training day."
    return values, days, error


def positive_count(field):
    """组数和次数只能是 SQLite 可安全保存的正整数，拒绝小数与超大输入。"""
    raw = request.form.get(field, "").strip()
    if not raw.isascii() or not raw.isdecimal() or len(raw) > 10:
        return None
    value = int(raw)
    return value if 1 <= value <= 2147483647 else None


@app.route("/workout-plan", methods=["GET", "POST"])
@app.route("/workout-plan/<int:plan_id>/edit", methods=["GET", "POST"])
def workout_plan(plan_id=None):
    """创建或编辑计划；保留未移除训练日的动作和原有 ID。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    plan = owned_plan(plan_id) if plan_id is not None else None
    existing_days = (
        query_db(
            "SELECT day_id, day_name FROM WorkDay WHERE plan_id = ?",
            (plan_id,),
        )
        if plan
        else []
    )
    values = (
        dict(plan)
        if plan
        else {"plan_name": "", "description": "", "date": ""}
    )
    # 兼容旧版 YYYYMMDD 日期，在 HTML 日期输入框中转换为标准格式。
    stored_date = str(values["date"] or "")
    if len(stored_date) == 8 and stored_date.isdigit():
        values["date"] = (
            f"{stored_date[:4]}-{stored_date[4:6]}-{stored_date[6:]}"
        )
    selected_days = [day["day_name"] for day in existing_days]
    error = None
    if request.method == "POST":
        values, selected_days, error = validate_plan_form()
        removed = [
            day
            for day in existing_days
            if day["day_name"] not in selected_days
        ]
        # 点击保存即应用训练日选择，取消的日期及其计划动作一并移除。
        if not error:
            db = get_db()
            with db:
                if plan:
                    db.execute(
                        "UPDATE WorkPlan SET plan_name = ?, des"
                        "cription = ?, date = ? "
                        "WHERE plan_id = ?",
                        (*values.values(), plan_id),
                    )
                    for day in removed:
                        db.execute(
                            "DELETE FROM WorkoutExercise WHERE day_" "id = ?",
                            (day["day_id"],),
                        )
                        db.execute(
                            "DELETE FROM WorkDay WHERE day_id = ?",
                            (day["day_id"],),
                        )
                else:
                    plan_id = db.execute(
                        "INSERT INTO WorkPlan (plan_name, descr"
                        "iption, date, user_id) VALUES (?, ?, ?"
                        ", ?)",
                        (*values.values(), session["user_id"]),
                    ).lastrowid
                # 新增日期只创建一次，不重建原来保留的日期。
                old_names = {day["day_name"] for day in existing_days}
                for day_name in selected_days:
                    if day_name not in old_names:
                        db.execute(
                            "INSERT INTO WorkDay (plan_id, day_name"
                            ") VALUES (?, ?)",
                            (plan_id, day_name),
                        )
            # 保存成功后提供明确反馈。
            flash(
                "Workout plan updated." if plan else "Workout plan created.",
                "success",
            )
            return redirect(url_for("add_plan_exercises", plan_id=plan_id))
    return render_template(
        "plan editor.html",
        plan=plan,
        values=values,
        selected_days=selected_days,
        weekdays=TRAINING_DAYS,
        error=error,
    ), (400 if error else 200)


@app.route("/workout-plan/<int:plan_id>/delete", methods=["GET", "POST"])
def delete_plan(plan_id):
    """先显示确认页，再按外键依赖顺序删除；独立训练历史始终保留。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    plan = owned_plan(plan_id)
    if request.method == "POST":
        if request.form.get("confirm") != "yes":
            abort(400, description="Please confirm deletion.")
        db = get_db()
        with db:
            db.execute(
                "DELETE FROM WorkoutExercise WHERE day_id IN "
                "(SELECT day_id FROM WorkDay WHERE plan_id = ?)",
                (plan_id,),
            )
            db.execute("DELETE FROM WorkDay WHERE plan_id = ?", (plan_id,))
            db.execute("DELETE FROM WorkPlan WHERE plan_id = ?", (plan_id,))
        # 保存成功后提供明确反馈。
        flash("Workout plan deleted.", "success")
        return redirect(url_for("plans"))
    return render_template(
        "confirm deletion.html",
        title="Delete workout plan",
        item_name=plan["plan_name"],
        message=(
            "This cannot be undone. Deleting a plan also removes its "
            "training days and planned exercises. "
            "Recorded workout history is kept."
        ),
        cancel_url=url_for("plans"),
    )


@app.route("/workout-plan/<int:plan_id>/exercises", methods=["GET", "POST"])
def add_plan_exercises(plan_id):
    """添加动作前校验训练日归属、动作是否存在，以及组数和次数。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    plan = owned_plan(plan_id)
    error = None
    if request.method == "POST":
        day_id = request.form.get("day_id", "")
        exercise_id = request.form.get("exercise_id", "")
        sets, reps = positive_count("sets"), positive_count("reps")
        day = query_db(
            "SELECT day_id FROM WorkDay WHERE day_id = ? AND plan_id = ?",
            (day_id, plan_id),
            one=True,
        )
        exercise = available_exercise(exercise_id)
        if day is None or exercise is None:
            error = "Select a valid training day and exercise."
        elif sets is None or reps is None:
            error = "Sets and reps must be whole numbers from 1 to 2147483647."
        else:
            db = get_db()
            with db:
                db.execute(
                    "INSERT INTO WorkoutExercise (day_id, e"
                    "xercise_id, sets, reps) "
                    "VALUES (?, ?, ?, ?)",
                    (day_id, exercise_id, sets, reps),
                )
            # 保存成功后提供明确反馈。
            flash("Exercise added to plan.", "success")
            return redirect(url_for("add_plan_exercises", plan_id=plan_id))
    days = query_db(
        "SELECT day_id, day_name FROM WorkDay W"
        "HERE plan_id = ? ORDER BY day_id",
        (plan_id,),
    )
    exercises = available_exercises()
    plan_exercises = query_db(
        "SELECT we.workout_exercise_id, we.day_"
        "id, d.day_name, e.exercise_name, "
        "e.equipment, we.sets, we.reps FROM WorkoutExercise we "
        "JOIN WorkDay d ON we.day_id = d.day_id"
        " JOIN Exercise e ON we.exercise_id = e"
        ".exercise_id "
        "WHERE d.plan_id = ? ORDER BY d.day_id,"
        " we.workout_exercise_id",
        (plan_id,),
    )
    return render_template(
        "add exercises.html",
        plan=plan,
        days=days,
        exercises=exercises,
        plan_exercises=plan_exercises,
        error=error,
    ), (400 if error else 200)


@app.route(
    "/workout-plan/<int:plan_id>/exercises/<int:entry_id>/edit",
    methods=["GET", "POST"],
)
@app.route(
    "/workout-plan/<int:plan_id>/exercises/<int:entry_id>/delete",
    methods=["GET", "POST"],
    endpoint="delete_plan_exercise",
)
def edit_plan_exercise(plan_id, entry_id):
    """仅编辑或移除当前计划中的动作；伪造其他计划的动作 ID 返回 404。"""
    if "user_id" not in session:
        return redirect(url_for("login"))
    owned_plan(plan_id)
    entry = query_db(
        "SELECT we.workout_exercise_id, we.sets, we.reps, e.exercise_name "
        "FROM WorkoutExercise we JOIN WorkDay d ON we.day_id = d.day_id "
        "JOIN Exercise e ON we.exercise_id = e.exercise_id "
        "WHERE we.workout_exercise_id = ? AND d"
        ".plan_id = ?",
        (entry_id, plan_id),
        one=True,
    )
    if entry is None:
        abort(404)
    cancel_url = url_for("add_plan_exercises", plan_id=plan_id)
    deleting = request.endpoint == "delete_plan_exercise"
    error = None
    if request.method == "POST":
        db = get_db()
        if deleting:
            if request.form.get("confirm") != "yes":
                abort(400, description="Please confirm deletion.")
            with db:
                db.execute(
                    "DELETE FROM WorkoutExercise WHERE work"
                    "out_exercise_id = ?",
                    (entry_id,),
                )
        else:
            sets, reps = positive_count("sets"), positive_count("reps")
            if sets is None or reps is None:
                error = (
                    "Sets and reps must be whole numbers from 1 to 2147483647."
                )
            else:
                with db:
                    db.execute(
                        "UPDATE WorkoutExercise SET sets = ?, reps = ? "
                        "WHERE workout_exercise_id = ?",
                        (sets, reps, entry_id),
                    )
        if not error:
            flash(
                "Exercise removed." if deleting else "Exercise updated.",
                "success",
            )
            return redirect(cancel_url)
    if deleting:
        return render_template(
            "confirm deletion.html",
            title="Remove planned exercise",
            item_name=entry["exercise_name"],
            message=(
                "This removes the exercise from this plan. "
                "Recorded workout history is kept."
            ),
            cancel_url=cancel_url,
        )
    return render_template(
        "exercise editor.html", entry=entry, error=error, cancel_url=cancel_url
    ), (400 if error else 200)


if __name__ == "__main__":
    # 默认关闭调试页面，使 500 错误显示友好提示而不是内部异常。
    app.run(debug=False)
