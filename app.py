import os
import sqlite3

from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, ".venv", "database.db")
os.makedirs(os.path.dirname(DATABASE), exist_ok=True)


# Initialize Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = "gymtraker_secret_key"


def init_db():
    with sqlite3.connect(DATABASE) as conn:
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
                db.execute(
                    """
                    INSERT INTO User (user_name, email, password)
                    VALUES (?, ?, ?);
                    """,
                    (user_name, email, password),
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
        email = request.form["email"]
        password = request.form["password"]

        # Query the database for the user
        user_sql = """
            SELECT user_id, user_name, email, password
            FROM User
            WHERE email = ?;
        """
        user = query_db(user_sql, (email,), one=True)

        if user is None:
            error = "Incorrect email"
        elif user["password"] != password:
            error = "Incorrect password"
        else:
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


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/training/<int:id>")
def training(id):
    # Show one workout exercise based on workout_exercise_id
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
        WHERE WorkoutExercise.workout_exercise_id = ?;
    """

    result = query_db(sql, (id,), one=True)

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
