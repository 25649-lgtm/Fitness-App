import os
import secrets
import sqlite3
from contextlib import closing
from werkzeug.security import check_password_hash, generate_password_hash

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 测试可通过环境变量使用临时数据库；正常运行仍使用原来的数据库。
DATABASE = os.environ.get(
    "GYMTRACKER_DATABASE", os.path.join(BASE_DIR, ".venv", "database.db")
)
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)


# 初始化应用；优先读取环境密钥，本地开发则使用持久化的随机密钥文件。
app = Flask(__name__)


def load_secret_key():
    """让密钥保持私密且重启后稳定，避免使用代码中公开的固定值。"""
    configured = os.environ.get("GYMTRACKER_SECRET_KEY")
    if configured:
        if len(configured) < 32:
            raise ValueError("GYMTRACKER_SECRET_KEY must contain at least 32 characters")
        return configured
    os.makedirs(app.instance_path, exist_ok=True)
    key_path = os.path.join(app.instance_path, "secret_key")
    try:
        # 独占创建，已有文件绝不覆盖；密钥文件必须排除在版本控制之外。
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
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
            abort(400, description="Form expired or invalid. Reload the page and try again.")


def init_db():
    # 创建这个健身应用需要的数据库表
    # conn 管理事务，closing 确保关闭连接，避免 Windows 下数据库文件被锁住。
    with closing(sqlite3.connect(DATABASE)) as conn, conn:
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS User (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                weight REAL,
                height REAL,
                goal TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS WorkPlan (
                plan_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                plan_name TEXT NOT NULL,
                description TEXT,
                date TEXT,
                FOREIGN KEY (user_id) REFERENCES User(user_id)
            )
            """
        )
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
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS WorkDay (
                day_id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER NOT NULL,
                day_name TEXT NOT NULL,
                FOREIGN KEY (plan_id) REFERENCES WorkPlan(plan_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS Exercise (
                exercise_id INTEGER PRIMARY KEY AUTOINCREMENT,
                exercise_name TEXT NOT NULL,
                description TEXT,
                equipment TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS WorkoutExercise (
                workout_exercise_id INTEGER PRIMARY KEY AUTOINCREMENT,
                day_id INTEGER NOT NULL,
                exercise_id INTEGER NOT NULL,
                sets INTEGER,
                reps INTEGER,
                FOREIGN KEY (day_id) REFERENCES WorkDay(day_id),
                FOREIGN KEY (exercise_id) REFERENCES Exercise(exercise_id)
            )
            """
        )
        conn.execute(
            """
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
            """
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
                    ("Shoulder Press",
                     "Overhead pressing movement",
                     "Dumbbells"),
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
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # 创建账户前检查表单内容
        if not user_name or not email or not password:
            error = "Please fill in all fields."
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
                    INSERT INTO User (user_name, email, password, password_hashed)
                    VALUES (?, ?, ?, 1);
                    """,
                    (user_name, email, generate_password_hash(password)),
                )
                db.commit()
                return redirect(url_for("login"))

    return render_template("sign up.html", error=error)


@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    if "user_id" in session:
        return redirect(url_for("homepage"))
    if request.method == "POST":
        # 邮箱与注册时保持相同格式；缺失字段使用空字符串，避免直接报错。
        email = request.form.get("email", "").strip().lower()
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

    # 查找用户训练计划里的所有动作
    workout_sql = """
        SELECT
            WorkDay.day_name,
            Exercise.exercise_name,
            Exercise.equipment,
            WorkoutExercise.sets,
            WorkoutExercise.reps
        FROM WorkoutExercise
        JOIN WorkDay
            ON WorkoutExercise.day_id = WorkDay.day_id
        JOIN WorkPlan
            ON WorkDay.plan_id = WorkPlan.plan_id
        JOIN Exercise
            ON WorkoutExercise.exercise_id = Exercise.exercise_id
        WHERE WorkPlan.user_id = ?
        ORDER BY WorkDay.day_id;
    """
    workouts = query_db(workout_sql, (user_id,))

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

    # 统计训练记录并显示在进度卡片中
    stats_sql = """
        SELECT
            COUNT(*) AS workout_count,
            COUNT(DISTINCT exercise_id) AS exercise_count
        FROM WorkNotes
        WHERE user_id = ?;
    """
    stats = query_db(stats_sql, (user_id,), one=True)

    return render_template(
        "homepage.html",
        user=user,
        workouts=workouts,
        recent_notes=recent_notes,
        stats=stats,
    )


@app.route("/logout", methods=["POST"])
def logout():
    # 退出会改变登录状态，因此只允许通过带有效 CSRF 令牌的表单提交。
    session.clear()
    return redirect(url_for("login"))


@app.route("/training/<int:id>")
def training(id):
    # 训练详情属于私人数据，未登录用户先返回登录页。
    if "user_id" not in session:
        return redirect(url_for("login"))
    # 同时按动作记录 ID 和当前用户筛选，防止修改网址后查看他人的训练。
    sql = """
        SELECT
            WorkoutExercise.workout_exercise_id,
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
        return "Training not found", 404

    return str(dict(result))


@app.route("/exercises")
def exercises():
    # Show all exercises
    sql = """
        SELECT
            exercise_id,
            exercise_name,
            description,
            equipment
        FROM Exercise
        ORDER BY exercise_name;
    """

    results = query_db(sql)

    return render_template("exercises.html", exercises=results)


@app.route("/notes", methods=["GET", "POST"])
def notes():
    if "user_id" not in session:
        return redirect(url_for("login"))

    error = None

    if request.method == "POST":
        exercise_id = request.form.get("exercise_id", type=int)
        date = request.form.get("date", "").strip()
        weight = request.form.get("weight", type=float)
        sets = request.form.get("sets", type=int)
        reps = request.form.get("reps", type=int)
        note_text = request.form.get("notes", "").strip()

        if not exercise_id or not date or not sets or not reps:
            error = (
                "Please complete the exercise, date, "
                "sets and reps fields."
            )

        else:
            db = get_db()

            db.execute(
                """
                INSERT INTO WorkNotes (
                    user_id,
                    exercise_id,
                    date,
                    weight,
                    sets,
                    reps,
                    notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    session["user_id"],
                    exercise_id,
                    date,
                    weight,
                    sets,
                    reps,
                    note_text,
                ),
            )
            db.commit()

            return redirect(url_for("notes"))

    # 只显示当前用户自己的训练记录
    sql = """
        SELECT
            WorkNotes.notes_id,
            User.user_name,
            Exercise.exercise_name,
            WorkNotes.date,
            WorkNotes.weight,
            WorkNotes.sets,
            WorkNotes.reps,
            WorkNotes.notes
        FROM WorkNotes
        JOIN User
            ON WorkNotes.user_id = User.user_id
        JOIN Exercise
            ON WorkNotes.exercise_id = Exercise.exercise_id
        WHERE WorkNotes.user_id = ?
        ORDER BY WorkNotes.date DESC, WorkNotes.notes_id DESC;
    """

    results = query_db(sql, (session["user_id"],))
    exercise_options = query_db(
        """
        SELECT
            exercise_id,
            exercise_name
        FROM Exercise
        ORDER BY exercise_name;
        """
    )

    return render_template(
        "work note.html",
        notes=results,
        exercises=exercise_options,
        error=error,
    )


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
    if "user_id" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        db = get_db()

        db.execute(
            """
            UPDATE User
            SET
                user_name = ?,
                weight = ?,
                height = ?,
                goal = ?
            WHERE user_id = ?;
            """,
            (
                request.form.get("user_name", "").strip(),
                request.form.get("weight", type=float),
                request.form.get("height", type=float),
                request.form.get("goal", "").strip(),
                session["user_id"],
            ),
        )
        db.commit()

        session["user_name"] = request.form.get("user_name", "").strip()

        return redirect(url_for("profile"))

    user = query_db(
        """
        SELECT
            user_name,
            email,
            weight,
            height,
            goal
        FROM User
        WHERE user_id = ?;
        """,
        (session["user_id"],),
        one=True,
    )

    return render_template("profile.html", user=user)


@app.route("/workout-plan", methods=["GET", "POST"])
def workout_plan():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    error = None

    if request.method == "POST":
        plan_name = request.form.get("plan_name", "").strip()
        description = request.form.get("description", "").strip()
        date = request.form.get("date", "").replace("-", "")

        # 创建计划前检查重要资料
        if not plan_name:
            error = "Please enter a plan name."

        elif not date:
            error = "Please select a start date."

        elif not request.form.getlist("training_days"):
            error = "Please select at least one training day."

        else:
            db = get_db()

            cursor = db.execute(
                """
                INSERT INTO WorkPlan (
                    user_id,
                    plan_name,
                    description,
                    date
                )
                VALUES (?, ?, ?, ?);
                """,
                (
                    user_id,
                    plan_name,
                    description,
                    int(date)
                )
            )

            plan_id = cursor.lastrowid

            # 为每一个选择的训练日建立一条 WorkDay 记录
            selected_days = request.form.getlist("training_days")

            for day_name in selected_days:
                db.execute(
                    """
                    INSERT INTO WorkDay (
                        plan_id,
                        day_name
                    )
                    VALUES (?, ?);
                    """,
                    (plan_id, day_name)
                )

            db.commit()

            db.commit()

            return redirect(
                url_for(
                    "add_plan_exercises",
                    plan_id=plan_id
                )
                )

    return render_template(
        "workout plan.html",
        error=error
                )


@app.route(
    "/workout-plan/<int:plan_id>/exercises",
    methods=["GET", "POST"]
        )
def add_plan_exercises(plan_id):
    # 检查用户是否登录
    if "user_id" not in session:
        return redirect(url_for("login"))

    user_id = session["user_id"]
    # 检查这个计划是不是当前用户的
    # 防止用户修改其他人的计划
    plan = query_db(
        """
        SELECT
            plan_id,
            plan_name,
            description
        FROM WorkPlan
        WHERE plan_id = ?
        AND user_id = ?;
        """,
        (plan_id, user_id),
        one=True,
    )

    if plan is None:
        return "Workout plan not found", 404

    # 如果用户提交 Add Exercise 表单
    if request.method == "POST":

        day_id = request.form.get("day_id")
        exercise_id = request.form.get("exercise_id")
        sets = request.form.get("sets")
        reps = request.form.get("reps")

        # 检查必须的数据
        if day_id and exercise_id:

            # 确认选择的训练日属于这个 plan
            day = query_db(
                """
                SELECT day_id
                FROM WorkDay
                WHERE day_id = ?
                AND plan_id = ?;
                """,
                (day_id, plan_id),
                one=True,
            )

            if day is not None:

                db = get_db()

                db.execute(
                    """
                    INSERT INTO WorkoutExercise (
                        day_id,
                        exercise_id,
                        sets,
                        reps
                    )
                    VALUES (?, ?, ?, ?);
                    """,
                    (
                        day_id,
                        exercise_id,
                        sets,
                        reps,
                    ),
                )

                db.commit()

        # 添加完成后重新加载当前页面
        return redirect(
            url_for(
                "add_plan_exercises",
                plan_id=plan_id
            )
        )

    # 查询这个 Plan 的训练日
    days = query_db(
        """
        SELECT
            day_id,
            day_name
        FROM WorkDay
        WHERE plan_id = ?
        ORDER BY day_id;
        """,
        (plan_id,),
    )

    # 查询所有可以添加的动作
    exercises = query_db(
        """
        SELECT
            exercise_id,
            exercise_name,
            equipment
        FROM Exercise
        ORDER BY exercise_name;
        """
    )

    # 查询当前已经添加到计划中的动作
    plan_exercises = query_db(
        """
        SELECT
            WorkoutExercise.workout_exercise_id,
            WorkoutExercise.day_id,
            WorkDay.day_name,
            Exercise.exercise_name,
            Exercise.equipment,
            WorkoutExercise.sets,
            WorkoutExercise.reps

        FROM WorkoutExercise

        JOIN WorkDay
            ON WorkoutExercise.day_id =
               WorkDay.day_id

        JOIN Exercise
            ON WorkoutExercise.exercise_id =
               Exercise.exercise_id

        WHERE WorkDay.plan_id = ?

        ORDER BY
            WorkDay.day_id,
            WorkoutExercise.workout_exercise_id;
        """,
        (plan_id,),
    )

    return render_template(
        "add exercises.html",
        plan=plan,
        days=days,
        exercises=exercises,
        plan_exercises=plan_exercises,
    )


if __name__ == "__main__":
    app.run(debug=True)
