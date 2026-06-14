import os
from flask import Flask, g
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, '.venv', 'database.db')


# initialization app
app = Flask(__name__)

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


@app.route("/")
def hello_world():
    # home page - TrainingtypeID, Trainer, shoulder and ImageURL
    sql = """
                SELECT Training.TrainingtypeID, Trainer.Name, Training.Shoulder, Training.ImageURL
                FROM Training
                JOIN Trainer ON Training.UserID = Trainer.UserID;"""
    results = query_db(sql)
    return str(results)

@app.route("/training/<int:id>")
def training(id):
    # just one training based on the ID
    sql = """
                SELECT Training.TrainingtypeID, Trainer.Name, Training.Shoulder, Training.ImageURL
                FROM Training
                JOIN Trainer ON Training.UserID = Trainer.UserID
                WHERE Training.TrainingtypeID = ?;"""
    result = query_db(sql, (id,), one=True)
    if result is None:
        return "Training not found", 404
    return str(result)

if __name__ == "__main__":
    app.run(debug=True)