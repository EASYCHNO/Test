const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
app.use(bodyParser.json());

// Подключение к базе данных SQLite
const db = new sqlite3.Database('./Test.db', (err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err.message);
  } else {
    console.log('Успешное подключение к базе данных.');
  }
});

// Middleware для парсинга JSON
app.use(express.json());


const upload = multer({ dest: 'uploads/' }); // Загруженные файлы будут сохраняться в папку 'uploads/'

/*const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/');
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + '-' + file.originalname); // Генерируем уникальное имя файла
  }
});*/

//const upload = multer({ storage: storage });

// Получение списка заказов с файлами
app.get('/orderswithfiles', (req, res) => {
  const sql = `
    SELECT Orders.OrderID, Users.Login, Orders.OrderDate, OrderStatuses.StatusName, Files.FileName, Files.FilePath, Files.FileID, Users.Surname, Users.Name, Users.Lastname, Orders.OrderPrice
    FROM Orders 
    INNER JOIN OrderFiles ON Orders.OrderID = OrderFiles.OrderID
    INNER JOIN Files ON OrderFiles.FileID = Files.FileID
    INNER JOIN Users ON Orders.UserID = Users.UserID
    INNER JOIN OrderStatuses ON Orders.StatusID = OrderStatuses.StatusID
  `;

  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Ошибка получения данных о заказах с файлами:', err.message);
      res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    } else {
      res.json(rows);
    }
  });
});

// Маршрут для загрузки файлов
app.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'Файл не был загружен' });
  }
  const inputFilePath = req.file.path;
  const fileName = req.file.originalname;
  const outputFilePath = path.join('uploads', `${path.parse(fileName).name}.pdf`);

convertFileToPDF(inputFilePath, outputFilePath, (err, result) => {
  if (err) {
    console.error('Ошибка конвертации файла:', err);
    return res.status(500).json({ error: 'Ошибка конвертации файла' });
  }

  // Сохраняем информацию о файле в базе данных
  const sql = 'INSERT INTO Files (FileName, FilePath) VALUES (?, ?)';
  const params = [fileName, outputFilePath]; // Сохраняем путь к PDF файлу
  db.run(sql, params, function (err) {
    if (err) {
      console.error('Ошибка сохранения информации о файле:', err.message);
      return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }

    res.json({ message: 'Файл успешно загружен и сконвертирован', fileId: this.lastID });
  });
});
});

// Возвращение информации о файле по ID
app.get('/files/:id', (req, res) => {
const fileId = req.params.id;
const sql = 'SELECT * FROM Files WHERE FileID = ?';
db.get(sql, [fileId], (err, row) => {
  if (err) {
    console.error('Ошибка получения информации о файле:', err.message);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } else {
    res.json(row);
  }
});
});

// Endpoint для регистрации пользователя
app.post('/users/register', (req, res) => {
  const { surname, name, lastname, email, login, password, roleID } = req.body;

  if (!surname || !name || !lastname || !email || !login || !password || !roleID) {
      console.log('Все поля обязательны для заполнения');
      return res.status(400).send('Все поля обязательны для заполнения');
  }

  // Хэширование пароля с использованием bcrypt
  const saltRounds = 10;
  const hashedPassword = bcrypt.hashSync(password, saltRounds);

  const sql = `INSERT INTO Users (Surname, Name, Lastname, Email, Login, Password, RoleID) 
               VALUES (?, ?, ?, ?, ?, ?, ?)`;
  db.run(sql, [surname, name, lastname, email, login, hashedPassword, roleID], function(err) {
      if (err) {
          console.log('Ошибка при регистрации пользователя:', err.message);
          return res.status(500).send('Ошибка при регистрации пользователя');
      }
      res.status(200).send('Пользователь успешно зарегистрирован');
  });
});

// Endpoint для входа пользователя
app.post('/users/login', (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
      console.log('Все поля обязательны для заполнения');
      return res.status(400).send('Все поля обязательны для заполнения');
  }

  const sql = `SELECT * FROM Users WHERE Login = ?`;
  db.get(sql, [login], (err, user) => {
      if (err) {
          console.log('Ошибка при входе пользователя:', err.message);
          return res.status(500).send('Ошибка при входе пользователя');
      }

      if (!user) {
          console.log('Неверный логин или пароль');
          return res.status(400).send('Неверный логин или пароль');
      }

      // Проверка пароля с использованием bcrypt
      const isMatch = bcrypt.compareSync(password, user.password);
      if (!isMatch) {
          console.log('Неверный логин или пароль');
          return res.status(400).send('Неверный логин или пароль');
      }

      res.status(200).send('Вход успешен');
  });
});


// Связка файла с заказом
app.post('/orderfiles', (req, res) => {
const { OrderID, FileID } = req.body;
const sql = 'INSERT INTO OrderFiles (OrderID, FileID) VALUES (?, ?)';
const params = [OrderID, FileID];
db.run(sql, params, function (err) {
  if (err) {
    console.error('Ошибка привязки файла к заказу:', err.message);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } else {
    res.json({ message: 'Файл успешно привязан к заказу' });
  }
});
});

// Получение списка заказов
app.get('/orders', (req, res) => {
const sql = 'SELECT * FROM Orders';
db.all(sql, [], (err, rows) => {
  if (err) {
    console.error('Ошибка получения заказов:', err.message);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } else {
    res.json(rows);
  }
});
});

// Получение списка файлов
app.get('/files', (req, res) => {
const sql = 'SELECT * FROM Files';
db.all(sql, [], (err, rows) => {
  if (err) {
    console.error('Ошибка получения заказов:', err.message);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } else {
    res.json(rows);
  }
});
});

// Создание нового заказа
app.post('/orders', (req, res) => {
const { UserID, OrderDate, StatusID } = req.body;
const sql = 'INSERT INTO Orders (UserID, OrderDate, StatusID) VALUES (?, ?, ?)';
const params = [UserID, OrderDate, StatusID];
db.run(sql, params, function (err) {
  if (err) {
    console.error('Ошибка создания заказа:', err.message);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } else {
    console.log(`Создан заказ с ID: ${this.lastID}`);
    res.status(201).json({ message: 'Заказ успешно создан', orderID: this.lastID });
  }
});
});

// Обновление статуса заказа
app.put('/orders/:id', (req, res) => {
const orderId = req.params.id;
const { StatusID } = req.body;
const sql = 'UPDATE Orders SET StatusID = ? WHERE OrderID = ?';
const params = [StatusID, orderId];
db.run(sql, params, function (err) {
  if (err) {
    console.error('Ошибка обновления статуса заказа:', err.message);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } else {
    console.log(`Обновлен статус заказа с ID: ${orderId}`);
    res.json({ message: 'Статус заказа успешно обновлен' });
  }
});
});

// Получение информации о пользователях
app.get('/users', (req, res) => {
const sql = 'SELECT * FROM Users';
db.all(sql, [], (err, rows) => {
  if (err) {
    console.error('Ошибка получения пользователей:', err.message);
    res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  } else {
    res.json(rows);
  }
});
});

// Поиск пользователя по ФИО
app.post('/users/search', async (req, res) => {
const { Surname, Name, Lastname } = req.body;

console.log('Полученные данные для поиска:', req.body); // Логирование полученных данных

let conditions = []; // Массив для условия WHERE
let params = []; // Массив параметров

// Формируем условия WHERE и массив параметров в зависимости от наличия значений
if (Surname) {
  conditions.push('Surname LIKE ?');
  params.push(`%${Surname}%`);
}
if (Name) {
  conditions.push('Name LIKE ?');
  params.push(`%${Name}%`);
}
if (Lastname) {
  conditions.push('Lastname LIKE ?');
  params.push(`%${Lastname}%`);
}

// Если ни одно из полей не предоставлено, возвращаем ошибку
if (params.length === 0) {
  return res.status(400).json({ error: 'Не указаны данные для поиска' });
}

// Формируем запрос с учетом условия WHERE, если есть параметры
const sql = `
  SELECT UserID 
  FROM Users 
  WHERE ${conditions.join(' AND ')}
`;

try {
  const row = await new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });

  res.json({ UserID: row?.UserID || 0 });
} catch (error) {
  console.error('Ошибка при поиске пользователя:', error.message);
  res.status(500).json({ error: 'Внутренняя ошибка сервера' });
  }
});

// Добавление нового пользователя
app.post('/users/add', (req, res) => {
  const { Surname, Name, Lastname, Login, Password } = req.body;

  console.log('Полученные данные для добавления пользователя:', req.body); // Логирование полученных данных

  // Проверка наличия всех необходимых данных
  if (!Surname || !Name || !Lastname || !Login || !Password) {
    console.error('Не все обязательные поля заполнены:', req.body);
    return res.status(400).json({ error: 'Все поля обязательны для заполнения' });
  }

  // Хеширование пароля
  bcrypt.hash(Password, 10, (err, hash) => {
    if (err) {
      console.error('Ошибка при хешировании пароля:', err.message);
      return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }

    // Вставка данных пользователя в базу данных
    const sql = 'INSERT INTO Users (Surname, Name, Lastname, Login, Password, RoleID) VALUES (?, ?, ?, ?, ?, ?)';
    const params = [Surname, Name, Lastname, Login, hash, 2]; // Устанавливаем RoleID в значение 2
    db.run(sql, params, function (err) {
      if (err) {
        console.error('Ошибка при добавлении пользователя:', err.message);
        return res.status(500).json({ error: 'Внутренняя ошибка сервера' });
      }

      console.log(`Пользователь ${Login} успешно добавлен`);
      res.json({ UserID: this.lastID });
    });
  });
});

app.post('/localorders', (req, res) => {
  console.log(req.body);

  const {localFileName, localOrderPrice, ownPaper } = req.body;
  const currentDate = new Date().toISOString(); // Преобразование в ISO 8601
  const sql = 'INSERT INTO LocalOrders (LocalFileName, LocalOrderDate, LocalOrderPrice, OwnPaper) VALUES (?, ?, ?, ?)';
  const params = [localFileName, currentDate, localOrderPrice, ownPaper];

  console.log(sql);

  db.run(sql, params, function (err) {
    if (err) {
      console.error('Ошибка создания локального заказа:', err.message);
      res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    } else {
      console.log(`Создан локальный заказ с ID: ${this.lastID}`);
      res.status(201).json({ message: 'Локальный заказ успешно создан', localOrderID: this.lastID });
    }
  });
});

app.get('/localorders', (req, res) => {
  const sql = 'SELECT * FROM LocalOrders';
  db.all(sql, [], (err, rows) => {
    if (err) {
      console.error('Ошибка получения локальных заказов:', err.message);
      res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    } else {
      res.json(rows);
    }
  });
});

// Маршрут для получения выборки выполненных заказов
app.get('/completedordersall', (req, res) => {
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  const sql = `
      SELECT
      c.CompletedOrderID,
      c.LocalOrderID,
      c.PrintDate,
      c.PaperCount,
      c.TotalPrice,
      c.IsLocal
    FROM CompletedOrders c
    JOIN LocalOrders l ON c.LocalOrderID = l.LocalOrderID

  `;

  db.all(sql, [startDate, endDate], (err, rows) => {
      if (err) {
          res.status(500).send({ error: err.message });
          return;
      }
      res.json(rows);
  });
});

app.get('/localorders/latest', (req, res) => {
  const sql = "SELECT LocalOrderID FROM LocalOrders ORDER BY LocalOrderID DESC LIMIT 1";

  db.get(sql, [], (err, row) => {
      if (err) {
          res.status(500).send({ error: err.message });
          return;
      }
      res.json(row ? row.LocalOrderID : null);
  });
});



// Маршрут для получения выборки выполненных заказов
app.get('/completedorders', (req, res) => {
  const startDate = req.query.startDate;
  const endDate = req.query.endDate;

  console.log('Запрос на получение выборки выполненных заказов с датами:', startDate, endDate);

  const sql = `
        SELECT
        c.CompletedOrderID,
        c.LocalOrderID,
        c.PrintDate,
        c.PaperCount,
        c.TotalPrice,
        c.IsLocal
      FROM CompletedOrders c
      JOIN LocalOrders l ON c.LocalOrderID = l.LocalOrderID
      WHERE c.PrintDate BETWEEN ? AND ?
      `;

  db.all(sql, [startDate, endDate], (err, rows) => {
      if (err) {
          console.error('Ошибка при получении выборки выполненных заказов:', err);
          res.status(500).send({ error: err.message });
          return;
      }
      console.log('Получены данные выборки выполненных заказов:', rows);
      res.json(rows);
  });
});

// Маршрут для сохранения информации о выполненном заказе
app.post('/completedorders', (req, res) => {
  const { orderID, localOrderID, printDate, paperCount, totalPrice, isLocal } = req.body;

  console.log('Полученные данные о выполненном заказе:', orderID, localOrderID, printDate, paperCount, totalPrice, isLocal);

  const sql = `
      INSERT INTO CompletedOrders (OrderID, LocalOrderID, PrintDate, PaperCount, TotalPrice, IsLocal)
      VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.run(sql, [orderID, localOrderID, printDate, paperCount, totalPrice, isLocal], function (err) {
      if (err) {
          console.error('Ошибка при сохранении информации о выполненном заказе:', err);
          res.status(500).send({ error: err.message });
          return;
      }
      console.log('Успешно сохранена информация о выполненном заказе:', orderID, localOrderID, printDate, paperCount, totalPrice, isLocal);
      res.json({ message: 'Заказ успешно сохранен в историю.' });
  });
});

app.get('/paperinventory', async (req, res) => {
  try {
    console.log('Получен запрос GET /paperinventory'); // Логируем запрос
    const result = await db.get('SELECT * FROM PaperInventory');
    console.log('Данные из базы данных:', result); // Логируем полученные данные
    res.json(result);
  } catch (error) {
    console.error('Ошибка при обработке GET /paperinventory:', error); // Логируем ошибку
    res.status(500).send('Ошибка сервера');
  }
});

app.put('/paperinventory', async (req, res) => {
  try {
    console.log('Получен запрос PUT /paperinventory', req.body); // Логируем запрос и тело запроса
    const { newQuantity } = req.body;

    await db.run('UPDATE PaperInventory SET Quantity = ?', [newQuantity]);
    console.log('Количество бумаги обновлено в базе данных'); // Логируем успешное обновление
    res.send('Количество бумаги обновлено');
  } catch (error) {
    console.error('Ошибка при обработке PUT /paperinventory:', error); // Логируем ошибку
    res.status(500).send('Ошибка сервера');
  }
});


// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});