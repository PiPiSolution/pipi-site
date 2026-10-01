// Серверная проверка логина администратора. Выполняется на сервере Netlify,
// а не в браузере, поэтому логин и пароль (хранятся в переменных окружения
// на Netlify, не в коде и не в git) никогда не попадают на страницу и не видны
// в просмотре исходного кода сайта.
//
// Как это настроено: в панели Netlify (Site settings → Environment variables)
// должны быть заданы три значения:
//   ADMIN_USERNAME     — логин администратора
//   ADMIN_PASSWORD     — пароль администратора
//   ADMIN_TOKEN_SECRET — случайная секретная строка для подписи токена входа
//
// Если вход успешен, функция выдаёт подписанный токен на 12 часов. Сайт хранит
// этот токен у себя в браузере и показывает админ-панель, пока токен не истёк.
// Подделать токен, не зная ADMIN_TOKEN_SECRET, нельзя.

const crypto = require('crypto');

function sign(payload, secret) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', secret).update(data).digest('base64');
  return data + '.' + sig;
}

exports.handler = async function (event) {
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, body: JSON.stringify({ error: 'Method not allowed' }) };
  }

  const { ADMIN_USERNAME, ADMIN_PASSWORD, ADMIN_TOKEN_SECRET } = process.env;
  if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !ADMIN_TOKEN_SECRET) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Сервер не настроен: не заданы переменные окружения администратора' })
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || '{}');
  } catch (e) {
    return { statusCode: 400, body: JSON.stringify({ error: 'Некорректный запрос' }) };
  }

  const { username, password } = body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = sign({ u: username, exp: Date.now() + 12 * 60 * 60 * 1000 }, ADMIN_TOKEN_SECRET);
    return { statusCode: 200, body: JSON.stringify({ token }) };
  }

  return { statusCode: 401, body: JSON.stringify({ error: 'Неверный логин или пароль' }) };
};
