"""使用独立临时数据库，自动验证密码安全、旧账户迁移和训练访问权限。"""

import os
import sqlite3
from contextlib import closing
import tempfile
import unittest

from werkzeug.security import check_password_hash

# app 在导入时会初始化数据库，所以必须先指定临时路径，避免修改真实数据。
test_storage = tempfile.TemporaryDirectory()
previous_database = os.environ.get("GYMTRACKER_DATABASE")
os.environ["GYMTRACKER_DATABASE"] = os.path.join(test_storage.name, "test.db")
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

    def register(self, email="test@example.com"):
        """提交虚构注册资料；不同邮箱用于创建多个测试账户。"""
        return self.client.post("/signup", data={
            "user_name": "Test", "email": email,
            "password": "example-password", "confirm_password": "example-password",
        })

    def login(self, password="example-password", email="test@example.com"):
        """模拟登录表单，允许传入不同密码和邮箱来测试成功与失败情况。"""
        return self.client.post("/", data={"email": email, "password": password})

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
        self.assertEqual(self.client.post("/", data={}).status_code, 200)
        with self.client.session_transaction() as session:
            self.assertNotIn("user_id", session)

    def test_duplicate_email_is_rejected(self):
        """确认同一个邮箱不能重复注册。"""
        self.register()
        self.assertIn(b"already exists", self.register().data)

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
        self.client.get("/logout")
        self.register("other@example.com")
        self.login(email="other@example.com")
        self.assertEqual(self.client.get(route).status_code, 404)


if __name__ == "__main__":
    # 直接运行此文件时，执行本文件中的全部 unittest 测试。
    unittest.main()
