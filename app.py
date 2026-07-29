import os
import sqlite3

from flask import Flask, g, render_template


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, ".venv", "database.db")


# Initialize Flask app
app = Flask(__name__)


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


@app.route("/")
def homepage():
    user_id = 1

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
        stats=stats
    )


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

    return str([dict(row) for row in results])


@app.route("/notes")
def notes():
    # Show all completed workout records
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
        ORDER BY WorkNotes.date DESC;
    """

    results = query_db(sql)

    return str([dict(row) for row in results])


if __name__ == "__main__":
    app.run(debug=True)
