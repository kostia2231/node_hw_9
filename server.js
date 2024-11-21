import express from "express";
import bcrypt from "bcrypt";
import cors from "cors";
import "dotenv/config";

const app = express();

app.use(express.json());
app.use(cors());

const port = process.env.PORT || 5555;

const users = [];

function checkMustChangePassword(req, res, next) {
  const { email } = req.body;
  const user = users.find((user) => user.email === email);

  if (user && user.mustChangePassword) {
    return res.status(403).json({
      error: "вам нужно сменить пароль перед дальнейшим использованием.",
    });
  }
  next();
}

function isAuthed(req, res, next) {
  const { email } = req.headers;
  const user = users.find((user) => user.email === email);

  if (!email || !user) {
    return res.status(401).json({ error: "вы не авторизованы" });
  }

  req.user = user;
  next();
}

app.post("/register", checkMustChangePassword, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "не все данные введены" });
  }

  if (users.find((user) => user.email === email)) {
    return res.status(400).json({ error: "этот и-мейл уже зарегистрирован" });
  }

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    users.push({ email, password: hashedPassword, mustChangePassword: false });

    res.status(201).send("пользователь зарегистрирован!");
  } catch (error) {
    console.error(error);
    res.status(500).send("ошибка регистрации");
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(404).json({ error: "пользователь не найден" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(401).json({ error: "неверный пароль" });
  }

  res.status(200).json({ message: "вход успешен!" });
});

app.post("/change-password", async (req, res) => {
  const { email, newPassword } = req.body;

  if (!email || !newPassword) {
    return res.status(400).json({ error: "почта и новый пароль обязательны!" });
  }

  const user = users.find((user) => user.email === email);
  if (!user) {
    return res.status(404).json({ error: "пользователь не найден" });
  }

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
    user.password = hashedPassword;
    user.mustChangePassword = false;
    res.status(200).json({ message: "пароль успешно изменен" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "ошибка сервера при смене пароля" });
  }
});

app.post("/delete-account", isAuthed, async (req, res) => {
  const { currentPassword } = req.body;
  const isMatch = await bcrypt.compare(currentPassword, req.user.password);

  if (!isMatch || !currentPassword) {
    return res.status(401).json({ error: "неверный пароль" });
  }

  const index = users.indexOf(req.user);
  if (index !== -1) {
    users.splice(index, 1);
  }

  res.status(200).json({ message: "аккаунт удален!" });
});

app.listen(port, () => {
  console.log(`сервер работает на порту: ${port}`);
});
