const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: "secret123",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(express.static(path.join(__dirname, "public")));

const db = new sqlite3.Database("database.db");

db.run(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
)
`);

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);

    db.run(
      "INSERT INTO users(email,password) VALUES(?,?)",
      [email, hash],
      (err) => {
        if (err) {
          return res.send("Пользователь уже существует");
        }

        res.redirect("/login.html");
      }
    );
  } catch (error) {
    res.send("Ошибка регистрации");
  }
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE email=?",
    [email],
    async (err, user) => {
      if (err) {
        return res.send("Ошибка сервера");
      }

      if (!user) {
        return res.send("Пользователь не найден");
      }

      const ok = await bcrypt.compare(password, user.password);

      if (!ok) {
        return res.send("Неверный пароль");
      }

      req.session.user = user;

      res.redirect("/profile");
    }
  );
});

app.get("/profile", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login.html");
  }

  res.sendFile(path.join(__dirname, "public", "profile.html"));
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

app.listen(PORT, () => {
  console.log(`Server started: http://localhost:${PORT}`);
});