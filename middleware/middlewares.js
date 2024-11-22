const users = [];

export function checkMustChangePassword(req, res, next) {
  const { email } = req.body;
  const user = users.find((user) => user.email === email);

  if (user && user.mustChangePassword) {
    return res.status(403).json({
      error: "вам нужно сменить пароль перед дальнейшим использованием.",
    });
  }
  next();
}

export function isAuthed(req, res, next) {
  const { email } = req.body;
  const user = users.find((user) => user.email === email);

  if (!email || !user) {
    return res.status(401).json({ error: "вы не авторизованы" });
  }

  req.user = user;
  next();
}

export function isAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ error: "вы не админ!" });
  }
  next();
}
