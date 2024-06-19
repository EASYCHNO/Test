const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const { transliterate } = require('transliteration');
const { PDFDocument } = require('pdf-lib');
const mammoth = require('mammoth');
const app = express();
const PORT = 3000;

app.use(express.json({ limit: '50mb', type: 'application/json', parameterLimit: 1000000 }));
app.use(express.urlencoded({ limit: '50mb', extended: true, parameterLimit: 1000000 }));

app.use(bodyParser.json());
app.use(express.json());

// Подключение к базе данных SQLite
const db = new sqlite3.Database('./Test.db', (err) => {
  if (err) {
    console.error('Ошибка подключения к базе данных:', err.message);
  } else {
    console.log('Успешное подключение к базе данных.');
  }
});

const SECRET_KEY = 'sunyaevkey';

// Настройка хранилища Multer
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Путь для сохранения файлов
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname); // Использование оригинального названия файла
  }
});


const uploads = multer({ storage: storage });

async function getPageCount(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.pdf') {
    const pdfBytes = fs.readFileSync(filePath);
    const pdfDoc = await PDFDocument.load(pdfBytes);
    return pdfDoc.getPageCount();
  } else if (ext === '.docx') {
    const result = await mammoth.extractRawText({ path: filePath });
    const text = result.value;
    // Уточняем количество страниц на основе количества символов и типичной длины страницы
    const charsPerPage = 1500; // Средняя длина страницы
    const pageCount = Math.ceil(text.length / charsPerPage);
    return pageCount;
  }
  throw new Error('Unsupported file type');
}

app.post('/upload', authenticateToken, uploads.single('file'), async (req, res) => {
  const file = req.file;
  const userId = req.user.userID;
  const orderDate = new Date().toISOString().split('T')[0];

  if (!file) {
      return res.status(400).send('Файл не загружен');
  }

  // Декодирование и транслитерация имени файла
  const decodedFileName = decodeURIComponent(escape(file.originalname));
  const transliteratedFileName = transliterate(decodedFileName);

  const newPath = path.join('uploads', transliteratedFileName);

  fs.rename(file.path, newPath, async (err) => {
      if (err) {
          console.error('Ошибка при переименовании файла:', err.message);
          return res.status(500).send('Ошибка при переименовании файла');
      }

      try {
        // Формирование URL с транслитерированным именем файла
        const fileUrl = `http://test-bri6.onrender.com/uploads/${encodeURIComponent(transliteratedFileName)}`;
        
        // Проверка типа файла и установка orderPrice
        const ext = path.extname(newPath).toLowerCase();
        let orderPrice;
        if (ext === '.pdf' || ext === '.docx') {
          const pageCount = await getPageCount(newPath);
          orderPrice = pageCount * 5;
        } else if (ext === '.jpg' || ext === '.jpeg' || ext === '.png') {
          orderPrice = 5;
        } else {
          return res.status(400).send('Неподдерживаемый тип файла');
        }

        db.serialize(() => {
          db.run(`INSERT INTO Files (FileName, FilePath) VALUES (?, ?)`, [decodedFileName, fileUrl], function (err) {
              if (err) {
                  console.error('Ошибка записи в таблицу Files:', err.message);
                  return res.status(500).send('Ошибка записи в таблицу Files');
              }

              const fileId = this.lastID;
              console.log(`Файл записан в таблицу Files с ID: ${fileId}`);

              db.run(`INSERT INTO Orders (UserID, OrderDate, StatusID, OrderPrice) VALUES (?, ?, ?, ?)`, [userId, orderDate, 1, orderPrice], function (err) {
                  if (err) {
                      console.error('Ошибка записи в таблицу Orders:', err.message);
                      return res.status(500).send('Ошибка записи в таблицу Orders');
                  }

                  const orderId = this.lastID;
                  console.log(`Заказ записан в таблицу Orders с ID: ${orderId}`);

                  db.run(`INSERT INTO OrderFiles (OrderID, FileID) VALUES (?, ?)`, [orderId, fileId], function (err) {
                      if (err) {
                          console.error('Ошибка записи в таблицу OrderFiles:', err.message);
                          return res.status(500).send('Ошибка записи в таблицу OrderFiles');
                      }

                      console.log('Файл успешно загружен и заказ оформлен.');
                      res.send('Файл успешно загружен и заказ оформлен.');
                  });
              });
          });
      });
      } catch (error) {
        console.error('Ошибка при обработке файла:', error.message);
        res.status(500).send('Ошибка при обработке файла');
      }
  });
});


// Чтение списка файлов
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

app.get('/files', (req, res) => {
  fs.readdir('uploads/', (err, files) => {
    if (err) {
      console.log('Ошибка чтения директории:', err.message);
      return res.status(500).send('Ошибка чтения директории');
    }
    res.send(files);
  });
});

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
      console.log('Заказы с файлами успешно получены:', rows);
      res.json(rows);
    }
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
      return;
    }

    if (!row) {
      console.warn(`Файл с ID ${fileId} не найден.`);
      res.status(404).json({ error: 'Файл не найден' });
      return;
    }

    // Преобразование относительного пути в абсолютный URL
    row.FilePath = `${req.protocol}://${req.get('host')}/uploads/${encodeURIComponent(path.basename(row.FilePath))}`;
    console.log(`Информация о файле с ID ${fileId} успешно получена:`, row);
    res.json(row); // Убедитесь, что данные отправляются в кодировке utf-8
  });
});

// Endpoint для регистрации работника
app.post('/users/register', (req, res) => {
  const { surname, name, lastname, email, login, password, roleID } = req.body;

  console.log("Регистрационные данные:", req.body); // Логируем полученные данные

  if (!surname || !name || !lastname || !email || !login || !password || !roleID) {
      console.log('Необходимо заполнить все поля для регистрации');
      return res.status(400).send('Необходимо заполнить все поля для регистрации');
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

// Endpoint для входа работника
app.post('/users/login', (req, res) => {
  const { login, password, roleID } = req.body;

  if (!login || !password) {
      console.log('Необходимо заполнить все поля для входа');
      return res.status(400).send('Необходимо заполнить все поля для входа');
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
      console.log('Проверка пароля для пользователя:', user);
      console.log('Введенный пароль:', password);
      console.log('Хэшированный пароль пользователя:', user.Password);
      
      // Добавим проверку на существование пароля в БД
      if (!user.Password) {
          console.log('Пароль пользователя отсутствует в базе данных');
          return res.status(400).send('Неверный логин или пароль');
      }

      const isMatch = bcrypt.compareSync(password, user.Password);
      if (!isMatch) {
          console.log('Неверный логин или пароль');
          return res.status(400).send('Неверный логин или пароль');
      }

      if (user.RoleID != 2){
        console.log('Пользователь не имеет доступа к программе для работников')
        return res.status(400).send('Нет доступа к программе для работников');
      }

      res.status(200).json(user);
  });
});


// Endpoint для регистрации клиента
app.post('/client/register', (req, res) => {
  console.log("Регистрационные данные:", req.body);
  const { surname, name, lastname, email, login, password, roleID } = req.body;

  if (!surname || !name || !lastname || !email || !login || !password || !roleID) {
      console.log('Необходимо заполнить все поля для регистрации');
      return res.status(400).send('Необходимо заполнить все поля для регистрации');
  }

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

// Маршрут для аутентификации клиента
app.post('/client/login', (req, res) => {
  const { login, password } = req.body;

  if (!login || !password) {
      console.log('Необходимо заполнить все поля для входа');
      return res.status(400).send('Необходимо заполнить все поля для входа');
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
      console.log('Проверка пароля для пользователя:', user);
      console.log('Введенный пароль:', password);
      console.log('Хэшированный пароль пользователя:', user.Password);

      if (!user.Password) {
          console.log('Пароль пользователя отсутствует в базе данных');
          return res.status(400).send('Неверный логин или пароль');
      }

      const isMatch = bcrypt.compareSync(password, user.Password);
      if (!isMatch) {
          console.log('Неверный логин или пароль');
          return res.status(400).send('Неверный логин или пароль');
      }

      if (user.RoleID != 3) {
          console.log('Пользователь не имеет доступа к программе для клиентов');
          return res.status(400).send('Нет доступа к программе для клиентов');
      }

      // Генерация JWT токена
      const token = jwt.sign({ userID: user.UserID, roleID: user.RoleID }, SECRET_KEY, { expiresIn: '1h' });
      res.status(200).json({ token });
  });
});

// Middleware для проверки JWT токена и извлечения userId
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    console.log('Токен отсутствует');
    return res.sendStatus(401);
  }

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.log('Ошибка верификации токена:', err.message);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

app.get('/protected', authenticateToken, (req, res) => {
  res.send('Доступ к защищенному ресурсу');
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
      console.log('Заказы успешно получены:', rows);
      res.json(rows);
    }
  });
});

// Получение списка файлов
app.get('/allfiles', (req, res) => {
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


app.post('/order', authenticateToken, (req, res) => {
  const { fileID, orderDate, statusID, orderPrice } = req.body;
  const userID = req.user.userID; // Получаем userID из проверенного токена

  if (!userID || !fileID || !orderDate || !statusID) {
      return res.status(400).send('Необходимо заполнить все поля заказа');
  }

  const sqlOrder = `INSERT INTO Orders (UserID, OrderDate, StatusID, OrderPrice) VALUES (?, ?, ?, ?)`;
  db.run(sqlOrder, [userID, orderDate, statusID, orderPrice], function (err) {
      if (err) {
          return res.status(500).send('Ошибка при создании заказа');
      }

      const orderID = this.lastID;
      const sqlOrderFile = `INSERT INTO OrderFiles (OrderID, FileID) VALUES (?, ?)`;
      db.run(sqlOrderFile, [orderID, fileID], function (err) {
          if (err) {
              return res.status(500).send('Ошибка при добавлении файла к заказу');
          }
          res.status(200).send({ orderID: orderID, message: 'Заказ успешно создан' });
      });
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

// Endpoint для получения актульных заказов пользователя
app.get('/client/orders', authenticateToken, (req, res) => {
  const userId = req.user.userID;

  const sql = `
    SELECT Orders.OrderID, Files.FileName, Orders.OrderDate, Orders.OrderPrice, OrderStatuses.StatusName
    FROM Orders
    JOIN OrderFiles ON Orders.OrderID = OrderFiles.OrderID
    JOIN Files ON OrderFiles.FileID = Files.FileID
    JOIN OrderStatuses ON Orders.StatusID = OrderStatuses.StatusID
    WHERE Orders.UserID = ? AND Orders.StatusID = 1
  `;

  db.all(sql, [userId], (err, orders) => {
    if (err) {
      console.log('Ошибка при получении заказов пользователя:', err.message);
      return res.status(500).send('Ошибка при получении заказов');
    }
    res.status(200).json(orders);
  });
});

// Endpoint для получения выполненных заказов пользователя
app.get('/client/completeorders', authenticateToken, (req, res) => {
  const userId = req.user.userID;

  const sql = `
    SELECT Orders.OrderID, Files.FileName, Orders.OrderDate, Orders.OrderPrice, OrderStatuses.StatusName
    FROM Orders
    JOIN OrderFiles ON Orders.OrderID = OrderFiles.OrderID
    JOIN Files ON OrderFiles.FileID = Files.FileID
    JOIN OrderStatuses ON Orders.StatusID = OrderStatuses.StatusID
    WHERE Orders.UserID = ? AND Orders.StatusID = 2
  `;

  db.all(sql, [userId], (err, orders) => {
    if (err) {
      console.log('Ошибка при получении заказов пользователя:', err.message);
      return res.status(500).send('Ошибка при получении заказов');
    }
    res.status(200).json(orders);
  });
});

//Endpoint для получения данных пользователя
app.get('/client/profile', (req, res) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).send('Токен не предоставлен');
  }

  jwt.verify(token.split(' ')[1], SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).send('Неверный токен');
    }

    const sql = `SELECT Name, Surname, Email FROM Users WHERE UserID = ?`;
    db.get(sql, [decoded.userID], (err, user) => {
      if (err) {
        console.log('Ошибка при получении профиля пользователя:', err.message);
        return res.status(500).send('Ошибка при получении профиля пользователя');
      }

      if (!user) {
        return res.status(404).send('Пользователь не найден');
      }

      res.status(200).json(user);
    });
  });
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Сервер запущен на порту ${PORT}`);
});