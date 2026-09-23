"""使用独立临时数据库，自动验证密码安全、旧账户迁移和训练访问权限。"""

import os
import re
from unittest.mock import patch
import sqlite3
from contextlib import closing
import tempfile
import unittest

from werkzeug.security import check_password_hash

# app 在导入时会初始化数据库，所以必须先指定临时路径，避免修改真实数据。
test_storage = tempfile.TemporaryDirectory()
previous_database = os.environ.get("GYMTRACKER_DATABASE")
os.environ["GYMTRACKER_DATABASE"] = os.path.join(test_storage.name, "test.db")
with patch.dict(os.environ, {"GYMTRACKER_SECRET_KEY": "test-only-secret-key-with-at-least-32-characters"}):
    import app as gym
# 导入后恢复环境变量，避免影响同一进程中的其他代码。
if previous_database is None:
    os.environ.pop("GYMTRACKER_DATABASE", None)
else:
    os.environ["GYMTRACKER_DATABASE"] = previous_database


class AuthenticationTests(unittest.TestCase):
    """每项测试独立运行，检查账户验证与训练数据隔离是否正常。"""

    def setUp(self):
        """每次测试前清空临时业务数据，并创建全新的模拟浏览器客户端。"""
        # 先清理关联记录，再清理账户；保留初始化时生成的动作库。
        # closing 负责关闭连接，db 负责提交事务或在异常时回滚。
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            for table in (
                "WorkoutExercise", "WorkNotes", "WorkDay", "WorkPlan", "User"
            ):
                db.execute(f"DELETE FROM {table}")
        gym.app.config.update(TESTING=True, SECRET_KEY="test-only-key")
        self.client = gym.app.test_client()

    def post_form(self, route, data=None):
        """先读取真实页面中的令牌，再模拟浏览器提交表单。"""
        page = self.client.get("/", follow_redirects=True)
        token = re.search(rb'name="csrf_token" value="([^"]+)"', page.data).group(1).decode()
        return self.client.post(route, data={**(data or {}), "csrf_token": token})

    def register(self, email="test@example.com"):
        """提交虚构注册资料；不同邮箱用于创建多个测试账户。"""
        return self.post_form("/signup", data={
            "user_name": "Test", "email": email,
            "password": "example-password", "confirm_password": "example-password",
        })

    def login(self, password="example-password", email="test@example.com"):
        """模拟登录表单，允许传入不同密码和邮箱来测试成功与失败情况。"""
        return self.post_form("/", data={"email": email, "password": password})

    def test_registration_stores_salted_hashes(self):
        """确认不保存明文，并验证相同密码因随机盐而生成不同哈希。"""
        self.assertEqual(self.register().status_code, 302)
        self.register("second@example.com")
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            rows = db.execute("SELECT password, password_hashed FROM User").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0][0], rows[1][0])
        for stored, marker in rows:
            self.assertNotEqual(stored, "example-password")
            self.assertTrue(check_password_hash(stored, "example-password"))
            self.assertEqual(marker, 1)

    def test_correct_password_and_normalized_email(self):
        """确认正确密码可登录，邮箱大小写和首尾空格不影响验证。"""
        self.register()
        self.assertEqual(self.login(email=" TEST@EXAMPLE.COM ").status_code, 302)
        with self.client.session_transaction() as session:
            self.assertIn("user_id", session)

    def test_wrong_empty_and_missing_credentials_are_rejected(self):
        """确认错误、空白或缺失的登录资料不会建立登录会话。"""
        self.register()
        for password in ("wrong", ""):
            self.assertIn(b"Incorrect password", self.login(password).data)
        self.assertEqual(self.post_form("/", data={}).status_code, 200)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_duplicate_email_is_rejected(self):
        """确认同一个邮箱不能重复注册。"""
        self.register()
        self.assertIn(b"already exists", self.register().data)

    def test_csrf_rejects_invalid_tokens_on_all_write_routes(self):
        """所有写入入口都必须拒绝缺失、错误或其他会话的令牌。"""
        self.register()
        self.login()
        other_client = gym.app.test_client()
        other_page = other_client.get("/")
        foreign_token = re.search(
            rb'name="csrf_token" value="([^"]+)"', other_page.data
        ).group(1).decode()
        for route in ("/", "/signup", "/register", "/profile", "/notes",
                      "/workout-plan", "/workout-plan/1/exercises", "/logout"):
            for token in (None, "wrong", "错误令牌", foreign_token):
                with self.subTest(route=route, token=token):
                    data = {} if token is None else {"csrf_token": token}
                    self.assertEqual(self.client.post(route, data=data).status_code, 400)
        # 被拦截的退出请求不能清除当前登录状态。
        with self.client.session_transaction() as session:
            self.assertIn("user_id", session)

    def test_valid_forms_save_data_and_logout_requires_post(self):
        """真实页面均输出令牌，正常提交可保存数据，GET 退出不改变会话。"""
        self.register()
        self.login()
        for route in ("/homepage", "/profile", "/notes", "/workout-plan"):
            self.assertIn(b'name="csrf_token"', self.client.get(route).data)
        self.assertEqual(self.post_form("/profile", {
            "user_name": "Updated", "weight": "70", "height": "175", "goal": "Strength"
        }).status_code, 302)
        response = self.post_form("/workout-plan", {
            "plan_name": "Secure plan", "date": "2026-09-21", "training_days": "Monday"
        })
        self.assertEqual(response.status_code, 302)
        exercise_route = response.location
        self.assertIn(b'name="csrf_token"', self.client.get(exercise_route).data)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            day_id = db.execute("SELECT day_id FROM WorkDay").fetchone()[0]
            exercise_id = db.execute("SELECT exercise_id FROM Exercise LIMIT 1").fetchone()[0]
        self.assertEqual(self.post_form(exercise_route, {
            "day_id": day_id, "exercise_id": exercise_id, "sets": "3", "reps": "8"
        }).status_code, 302)
        self.assertEqual(self.post_form("/notes", {
            "exercise_id": exercise_id, "date": "2026-09-21", "weight": "20",
            "sets": "3", "reps": "8", "notes": "CSRF verified"
        }).status_code, 302)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT user_name FROM User").fetchone()[0], "Updated")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkoutExercise").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT notes FROM WorkNotes").fetchone()[0], "CSRF verified")
        self.assertEqual(self.client.get("/logout").status_code, 405)
        with self.client.session_transaction() as session:
            self.assertIn("user_id", session)
        self.assertEqual(self.post_form("/logout").status_code, 302)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_secret_key_persists_and_environment_takes_priority(self):
        """本地密钥重复加载保持一致，环境变量可覆盖，过短密钥被拒绝。"""
        with tempfile.TemporaryDirectory() as instance_dir:
            with patch.object(gym.app, "instance_path", instance_dir):
                with patch.dict(os.environ, {"GYMTRACKER_SECRET_KEY": ""}):
                    first = gym.load_secret_key()
                    self.assertGreaterEqual(len(first), 32)
                    self.assertEqual(first, gym.load_secret_key())
                with patch.dict(os.environ, {"GYMTRACKER_SECRET_KEY": "x" * 32}):
                    self.assertEqual(gym.load_secret_key(), "x" * 32)
                with patch.dict(os.environ, {"GYMTRACKER_SECRET_KEY": "short"}):
                    with self.assertRaises(ValueError):
                        gym.load_secret_key()

    def make_plan(self):
        """建立包含动作和独立历史记录的计划，供 CRUD 测试使用。"""
        self.register()
        self.login()
        response = self.post_form("/workout-plan", {
            "plan_name": "Original", "description": "Before", "date": "2026-09-23",
            "training_days": ["Monday", "Friday"],
        })
        self.assertEqual(response.status_code, 302)
        plan_id = int(response.location.split("/")[2])
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            day_id = db.execute("SELECT day_id FROM WorkDay WHERE plan_id = ? AND day_name = 'Monday'", (plan_id,)).fetchone()[0]
            exercise_id = db.execute("SELECT exercise_id FROM Exercise LIMIT 1").fetchone()[0]
        self.post_form(response.location, {"day_id": day_id, "exercise_id": exercise_id, "sets": "3", "reps": "8"})
        self.post_form("/notes", {"exercise_id": exercise_id, "date": "2026-09-23", "sets": "3", "reps": "8"})
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            entry_id = db.execute("SELECT workout_exercise_id FROM WorkoutExercise WHERE day_id = ?", (day_id,)).fetchone()[0]
        return plan_id, day_id, exercise_id, entry_id

    def test_plan_edit_preserves_days_and_confirms_removal(self):
        """保留日期的动作不能丢失；移除日期必须确认，历史记录不受影响。"""
        plan_id, day_id, _, entry_id = self.make_plan()
        route = f"/workout-plan/{plan_id}/edit"
        self.assertEqual(self.client.get(route).status_code, 200)
        values = {"plan_name": "Updated", "description": "After", "date": "2026-10-01",
                  "training_days": ["Monday", "Wednesday"], "confirm_remove_days": "yes"}
        self.assertEqual(self.post_form(route, values).status_code, 302)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT plan_name, description, date FROM WorkPlan WHERE plan_id = ?", (plan_id,)).fetchone(), ("Updated", "After", "2026-10-01"))
            self.assertEqual(db.execute("SELECT day_id FROM WorkoutExercise WHERE workout_exercise_id = ?", (entry_id,)).fetchone()[0], day_id)
        values.update(training_days=["Wednesday"], confirm_remove_days="")
        self.assertEqual(self.post_form(route, values).status_code, 400)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkoutExercise").fetchone()[0], 1)
        values["confirm_remove_days"] = "yes"
        self.assertEqual(self.post_form(route, values).status_code, 302)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkoutExercise").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes").fetchone()[0], 1)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_plan_invalid_input_does_not_change_data(self):
        """创建与编辑都拒绝空名称、无效日期及伪造训练日。"""
        plan_id, _, _, _ = self.make_plan()
        valid = {"plan_name": "Original", "date": "2026-09-23", "training_days": ["Monday", "Friday"]}
        for route in ("/workout-plan", f"/workout-plan/{plan_id}/edit"):
            for change in ({"plan_name": " "}, {"date": "2026-02-30"}, {"date": "abc"},
                           {"training_days": []}, {"training_days": ["Fake"]}):
                with self.subTest(route=route, change=change):
                    self.assertEqual(self.post_form(route, {**valid, **change}).status_code, 400)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkPlan").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT plan_name FROM WorkPlan").fetchone()[0], "Original")

    def test_exercise_edit_validation_and_confirmed_delete(self):
        """组数次数边界校验、正常更新、删除确认均通过数据库结果验证。"""
        plan_id, day_id, exercise_id, entry_id = self.make_plan()
        route = f"/workout-plan/{plan_id}/exercises"
        edit = f"{route}/{entry_id}/edit"
        delete = f"{route}/{entry_id}/delete"
        self.assertEqual(self.client.get(edit).status_code, 200)
        for field in ("sets", "reps"):
            for value in ("0", "-1", "1.5", "abc", "", "9" * 100):
                data = {"day_id": day_id, "exercise_id": exercise_id, "sets": "3", "reps": "8", field: value}
                self.assertEqual(self.post_form(route, data).status_code, 400)
                self.assertEqual(self.post_form(edit, data).status_code, 400)
        self.assertEqual(self.post_form(route, {"day_id": day_id, "exercise_id": "999999", "sets": "1", "reps": "1"}).status_code, 400)
        self.assertEqual(self.post_form(edit, {"sets": "1", "reps": "12"}).status_code, 302)
        self.assertEqual(self.client.get(delete).status_code, 200)
        self.assertEqual(self.post_form(delete).status_code, 400)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT sets, reps FROM WorkoutExercise WHERE workout_exercise_id = ?", (entry_id,)).fetchone(), (1, 12))
        self.assertEqual(self.post_form(delete, {"confirm": "yes"}).status_code, 302)
        self.assertEqual(self.client.get(edit).status_code, 404)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkoutExercise").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes").fetchone()[0], 1)

    def test_plan_delete_preserves_history_and_foreign_keys(self):
        """确认页和取消不删除数据；确认删除清理关联记录并保留训练历史。"""
        plan_id, _, _, _ = self.make_plan()
        route = f"/workout-plan/{plan_id}/delete"
        self.assertEqual(self.client.get(route).status_code, 200)
        self.assertEqual(self.post_form(route).status_code, 400)
        self.assertEqual(self.client.get(f"/workout-plan/{plan_id}/edit").status_code, 200)
        self.assertEqual(self.post_form(route, {"confirm": "yes"}).status_code, 302)
        self.assertEqual(self.post_form(route, {"confirm": "yes"}).status_code, 404)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            for table in ("WorkPlan", "WorkDay", "WorkoutExercise"):
                self.assertEqual(db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes").fetchone()[0], 1)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_management_routes_reject_cross_account_and_missing_csrf(self):
        """新路由拒绝无令牌、未登录和跨账户请求，伪造动作归属也不能通过。"""
        plan_id, day_id, exercise_id, entry_id = self.make_plan()
        routes = [f"/workout-plan/{plan_id}/edit", f"/workout-plan/{plan_id}/delete",
                  f"/workout-plan/{plan_id}/exercises/{entry_id}/edit",
                  f"/workout-plan/{plan_id}/exercises/{entry_id}/delete"]
        for route in routes:
            self.assertEqual(self.client.post(route, data={"confirm": "yes"}).status_code, 400)
        self.post_form("/logout")
        for route in routes:
            self.assertEqual(self.client.get(route).status_code, 302)
        self.register("other@example.com")
        self.login(email="other@example.com")
        for route in routes:
            self.assertEqual(self.client.get(route).status_code, 404)
            self.assertEqual(self.post_form(route, {"confirm": "yes"}).status_code, 404)
        # 另一个用户即使有自己的计划，也不能借用原用户的动作 ID 或训练日。
        response = self.post_form("/workout-plan", {"plan_name": "Other", "date": "2026-09-23", "training_days": ["Tuesday"]})
        other_route = response.location
        for action in ("edit", "delete"):
            self.assertEqual(self.post_form(f"{other_route}/{entry_id}/{action}", {"confirm": "yes"}).status_code, 404)
        self.assertEqual(self.post_form(other_route, {"day_id": day_id, "exercise_id": exercise_id, "sets": "3", "reps": "8"}).status_code, 400)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkoutExercise WHERE workout_exercise_id = ?", (entry_id,)).fetchone()[0], 1)

    def note_fixture(self):
        """建立一个有历史记录的账户，并取得其记录 ID。"""
        self.make_plan()
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            note_id, exercise_id = db.execute("SELECT notes_id, exercise_id FROM WorkNotes").fetchone()
        return note_id, {"exercise_id": exercise_id, "date": "2026-09-23",
                         "weight": "25.5", "sets": "3", "reps": "8", "notes": "Original"}

    def test_note_edit_updates_all_fields_and_keeps_identity(self):
        """编辑所有字段后记录 ID 不变，列表显示更新结果。"""
        note_id, values = self.note_fixture()
        route = f"/notes/{note_id}/edit"
        page = self.client.get(route)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'value="2026-09-23"', page.data)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            another_exercise = db.execute("SELECT exercise_id FROM Exercise WHERE exercise_id != ? LIMIT 1", (values["exercise_id"],)).fetchone()[0]
        values.update(exercise_id=another_exercise, date="2026-09-24", weight="0", sets="1", reps="12", notes="Updated record")
        self.assertEqual(self.post_form(route, values).status_code, 302)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            result = db.execute("SELECT exercise_id, date, weight, sets, reps, notes FROM WorkNotes WHERE notes_id = ?", (note_id,)).fetchone()
            self.assertEqual(result, (another_exercise, "2026-09-24", 0.0, 1, 12, "Updated record"))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes").fetchone()[0], 1)
        self.assertIn(b"Updated record", self.client.get("/notes").data)
        # 留空重量仍允许保存，使用 NULL 表示没有填写。
        values["weight"] = ""
        self.assertEqual(self.post_form(route, values).status_code, 302)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertIsNone(db.execute("SELECT weight FROM WorkNotes WHERE notes_id = ?", (note_id,)).fetchone()[0])

    def test_note_invalid_inputs_do_not_insert_or_update(self):
        """新建和编辑拒绝异常与边界输入，并保留原记录及用户表单内容。"""
        note_id, values = self.note_fixture()
        changes = [{"date": value} for value in ("", "2026-02-30", "abc")]
        changes += [{"weight": value} for value in ("-1", "NaN", "inf", "1e999", "abc")]
        changes += [{field: value} for field in ("sets", "reps") for value in ("", "0", "-1", "1.5", "abc", "9" * 100)]
        changes += [{"exercise_id": "999999"}, {"notes": "x" * 2001}]
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            original = db.execute("SELECT exercise_id, date, weight, sets, reps, notes FROM WorkNotes WHERE notes_id = ?", (note_id,)).fetchone()
        for route in ("/notes", f"/notes/{note_id}/edit"):
            for change in changes:
                with self.subTest(route=route, change=change):
                    response = self.post_form(route, {**values, **change})
                    self.assertEqual(response.status_code, 400)
            response = self.post_form(route, {**values, "date": "bad", "notes": "Keep my text"})
            self.assertIn(b"Keep my text", response.data)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT exercise_id, date, weight, sets, reps, notes FROM WorkNotes WHERE notes_id = ?", (note_id,)).fetchone(), original)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes").fetchone()[0], 1)

    def test_note_delete_requires_confirmation_and_preserves_plans(self):
        """确认前不删除，确认后只删除指定历史记录，计划和其他记录继续保留。"""
        note_id, values = self.note_fixture()
        self.post_form("/notes", values)
        route = f"/notes/{note_id}/delete"
        self.assertEqual(self.client.get(route).status_code, 200)
        self.assertEqual(self.post_form(route).status_code, 400)
        self.assertEqual(self.client.get(f"/notes/{note_id}/edit").status_code, 200)
        self.assertEqual(self.post_form(route, {"confirm": "yes"}).status_code, 302)
        for suffix in ("edit", "delete"):
            self.assertEqual(self.client.get(f"/notes/{note_id}/{suffix}").status_code, 404)
            self.assertEqual(self.post_form(f"/notes/{note_id}/{suffix}", {**values, "confirm": "yes"}).status_code, 404)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkPlan").fetchone()[0], 1)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkoutExercise").fetchone()[0], 1)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_note_routes_reject_cross_account_anonymous_and_csrf(self):
        """阻止跨账户、未登录及伪造令牌的编辑和删除，数据库保持不变。"""
        note_id, values = self.note_fixture()
        routes = [f"/notes/{note_id}/edit", f"/notes/{note_id}/delete"]
        for route in routes:
            for token in (None, "wrong"):
                data = {**values, "confirm": "yes"}
                if token is not None:
                    data["csrf_token"] = token
                self.assertEqual(self.client.post(route, data=data).status_code, 400)
        self.post_form("/logout")
        for route in routes:
            self.assertEqual(self.client.get(route).status_code, 302)
            self.assertEqual(self.post_form(route, {**values, "confirm": "yes"}).status_code, 302)
        self.register("other@example.com")
        self.login(email="other@example.com")
        for route in routes:
            self.assertEqual(self.client.get(route).status_code, 404)
            self.assertEqual(self.post_form(route, {**values, "confirm": "yes"}).status_code, 404)
        for suffix in ("edit", "delete"):
            self.assertEqual(self.client.get(f"/notes/999999/{suffix}").status_code, 404)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes WHERE notes_id = ?", (note_id,)).fetchone()[0], 1)

    def test_delete_pages_confirm_with_button_without_checkbox(self):
        """删除确认值由按钮提交，用户无需再勾选额外复选框。"""
        plan_id, _, _, entry_id = self.make_plan()
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            note_id = db.execute("SELECT notes_id FROM WorkNotes").fetchone()[0]
        for route in (f"/workout-plan/{plan_id}/delete",
                      f"/workout-plan/{plan_id}/exercises/{entry_id}/delete",
                      f"/notes/{note_id}/delete"):
            page = self.client.get(route)
            self.assertEqual(page.status_code, 200)
            self.assertNotIn(b'type="checkbox"', page.data)
            self.assertIn(b'type="submit" name="confirm" value="yes"', page.data)

    def dashboard_context(self, date):
        """固定本地日期并捕获模板数据，直接验证日期筛选和统计数值。"""
        from flask import template_rendered
        captured = []
        def capture(sender, template, context, **extra):
            captured.append(context)
        with template_rendered.connected_to(capture, gym.app):
            with patch.object(gym, "today_date", return_value=date):
                response = self.client.get("/homepage")
        self.assertEqual(response.status_code, 200)
        return response, captured[0]

    def test_today_filters_day_start_date_and_account(self):
        """今日显示所有已开始的本人计划，兼容旧日期，排除其他日期与他人计划。"""
        plan_id, day_id, exercise_id, entry_id = self.make_plan()
        today = gym.calendar_date(2026, 9, 28)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            user_id = db.execute("SELECT user_id FROM WorkPlan WHERE plan_id = ?", (plan_id,)).fetchone()[0]
            other_id = db.execute("INSERT INTO User (user_name, email, password, password_hashed) VALUES ('Other', 'isolated@example.com', 'unused', 1)").lastrowid
            for name, start, day, owner in (
                ("Future", "2026-10-01", "Monday", user_id),
                ("Wrong day", "2026-09-01", "Tuesday", user_id),
                ("Other user", "2026-09-01", "Monday", other_id),
                ("Legacy date", "20260928", "Monday", user_id),
            ):
                new_plan = db.execute("INSERT INTO WorkPlan (user_id, plan_name, date) VALUES (?, ?, ?)", (owner, name, start)).lastrowid
                new_day = db.execute("INSERT INTO WorkDay (plan_id, day_name) VALUES (?, ?)", (new_plan, day)).lastrowid
                db.execute("INSERT INTO WorkoutExercise (day_id, exercise_id, sets, reps) VALUES (?, ?, 2, 5)", (new_day, exercise_id))
        response, context = self.dashboard_context(today)
        self.assertEqual({row["plan_name"] for row in context["workouts"]}, {"Original", "Legacy date"})
        for row in context["workouts"]:
            self.assertIn(f'/training/{row["workout_exercise_id"]}'.encode(), response.data)
        response, context = self.dashboard_context(gym.calendar_date(2026, 9, 30))
        self.assertEqual(context["workouts"], [])
        self.assertIn(b"No exercises scheduled for today", response.data)
        self.assertNotIn(b">Start Workout</a>", response.data)

    def test_weekly_counts_monday_through_sunday_only(self):
        """验证上周日、本周一、本周日及下周一边界，并排除其他账户。"""
        plan_id, _, exercise_id, _ = self.make_plan()
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            user_id = db.execute("SELECT user_id FROM WorkPlan WHERE plan_id = ?", (plan_id,)).fetchone()[0]
            other_id = db.execute("INSERT INTO User (user_name, email, password, password_hashed) VALUES ('Other', 'weekly@example.com', 'unused', 1)").lastrowid
            for date, owner in (("2026-09-27", user_id), ("2026-09-28", user_id),
                                ("20261004", user_id), ("2026-10-05", user_id),
                                ("2026-09-29", other_id)):
                db.execute("INSERT INTO WorkNotes (user_id, exercise_id, date, sets, reps) VALUES (?, ?, ?, 3, 8)", (owner, exercise_id, date))
        for today in (gym.calendar_date(2026, 9, 28), gym.calendar_date(2026, 10, 4)):
            _, context = self.dashboard_context(today)
            self.assertEqual(context["stats"]["workout_count"], 2)
            self.assertEqual(context["stats"]["exercise_count"], 1)
            self.assertEqual(context["week_start"], gym.calendar_date(2026, 9, 28))
            self.assertEqual(context["week_last"], gym.calendar_date(2026, 10, 4))
        _, context = self.dashboard_context(gym.calendar_date(2026, 10, 5))
        self.assertEqual(context["stats"]["workout_count"], 1)
        _, context = self.dashboard_context(gym.calendar_date(2026, 11, 1))
        self.assertEqual(context["stats"]["workout_count"], 0)

    def test_start_workout_prefills_and_saves_actual_results(self):
        """训练页预填本人动作，错误输入不写入；保存实际结果后首页统计更新。"""
        _, _, exercise_id, entry_id = self.make_plan()
        route = f"/training/{entry_id}"
        with patch.object(gym, "today_date", return_value=gym.calendar_date(2026, 9, 28)):
            page = self.client.get(route)
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Record your results', page.data)
        self.assertIn(b'value="2026-09-28"', page.data)
        self.assertIn(b'value="3"', page.data)
        data = {"exercise_id": exercise_id, "date": "2026-09-28", "weight": "45.5", "sets": "4", "reps": "10", "notes": "Completed today"}
        self.assertEqual(self.client.post(route, data=data).status_code, 400)
        self.assertEqual(self.post_form(route, {**data, "sets": "-1"}).status_code, 400)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            other_exercise = db.execute("SELECT exercise_id FROM Exercise WHERE exercise_id != ? LIMIT 1", (exercise_id,)).fetchone()[0]
        self.assertEqual(self.post_form(route, {**data, "exercise_id": other_exercise}).status_code, 400)
        response = self.post_form(route, data)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith("/notes"))
        self.assertIn(b"Completed today", self.client.get("/notes").data)
        _, context = self.dashboard_context(gym.calendar_date(2026, 9, 28))
        self.assertEqual(context["stats"]["workout_count"], 1)
        self.post_form("/logout")
        self.register("intruder@example.com")
        self.login(email="intruder@example.com")
        self.assertEqual(self.post_form(route, data).status_code, 404)
        self.assertEqual(self.post_form("/training/999999", data).status_code, 404)
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            self.assertEqual(db.execute("SELECT weight, sets, reps FROM WorkNotes WHERE notes = 'Completed today'").fetchone(), (45.5, 4, 10))
            self.assertEqual(db.execute("SELECT COUNT(*) FROM WorkNotes").fetchone()[0], 2)

    def test_old_schema_migrates_once_and_preserves_login(self):
        """模拟旧数据库，验证密码迁移后可登录且重复初始化不会再次哈希。"""
        original = gym.DATABASE
        try:
            with tempfile.TemporaryDirectory() as legacy_dir:
                gym.DATABASE = os.path.join(legacy_dir, "legacy.db")
                # 故意创建不含 password_hashed 字段的旧表，并放入虚构明文密码。
                with closing(sqlite3.connect(gym.DATABASE)) as db, db:
                    db.execute("CREATE TABLE User (user_id INTEGER PRIMARY KEY, "
                               "user_name TEXT, email TEXT UNIQUE, password TEXT, "
                               "weight REAL, height REAL, goal TEXT)")
                    db.execute("INSERT INTO User (user_id, user_name, email, password) "
                               "VALUES (1, 'Test', 'test@example.com', 'example-password')")
                gym.init_db()
                with closing(sqlite3.connect(gym.DATABASE)) as db, db:
                    first = db.execute("SELECT password FROM User").fetchone()[0]
                self.assertTrue(check_password_hash(first, "example-password"))
                self.assertEqual(self.login().status_code, 302)
                # 再次初始化后，已迁移密码的哈希值应保持不变。
                gym.init_db()
                with closing(sqlite3.connect(gym.DATABASE)) as db, db:
                    second = db.execute("SELECT password FROM User").fetchone()[0]
                self.assertEqual(first, second)
        finally:
            # 即使测试失败，也要恢复数据库路径，避免影响后续测试。
            gym.DATABASE = original

    def test_training_requires_login_and_ownership(self):
        """验证匿名用户被重定向、本人可查看、其他账户及不存在记录返回 404。"""
        self.register()
        # 建立属于第一个测试账户的计划、训练日和动作记录。
        with closing(sqlite3.connect(gym.DATABASE)) as db, db:
            user_id = db.execute("SELECT user_id FROM User").fetchone()[0]
            plan_id = db.execute("INSERT INTO WorkPlan (user_id, plan_name) "
                                 "VALUES (?, 'Test plan')", (user_id,)).lastrowid
            day_id = db.execute("INSERT INTO WorkDay (plan_id, day_name) "
                                "VALUES (?, 'Monday')", (plan_id,)).lastrowid
            exercise_id = db.execute("SELECT exercise_id FROM Exercise LIMIT 1").fetchone()[0]
            training_id = db.execute("INSERT INTO WorkoutExercise (day_id, exercise_id) "
                                     "VALUES (?, ?)", (day_id, exercise_id)).lastrowid
        route = f"/training/{training_id}"
        self.assertEqual(self.client.get(route).status_code, 302)
        self.login()
        self.assertEqual(self.client.get(route).status_code, 200)
        self.assertEqual(self.client.get("/training/999999").status_code, 404)
        # 切换到另一个账户，确认同一条训练记录不能被跨账户读取。
        self.post_form("/logout")
        self.register("other@example.com")
        self.login(email="other@example.com")
        self.assertEqual(self.client.get(route).status_code, 404)


if __name__ == "__main__":
    # 直接运行此文件时，执行本文件中的全部 unittest 测试。
    unittest.main()
