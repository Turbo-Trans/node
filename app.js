const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const app = express();
var path = require("path");
const bcrypt = require("bcrypt");
const con = require("./components/db");
const auth = require('./components/auth');
const perm = require('./components/perm');



app.use(cors({
  origin: function(origin, callback) {
    callback(null, true);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use((req,res,next)=>{
	console.log(JSON.stringify({
		method: req.method,
		url: req.url,
		header: req.headers,
		body: req.body,
	},null,2));
	next();
})

app.use(bodyParser.json());
app.use("/", express.static(path.join(__dirname, "public")));


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Node sunucusu ${PORT} portunda baslatildi.`);
});


/*bcrypt.hash("123456", 12, (err, hashed) => {
  if (err) throw err;
  console.log("Hashed:", hashed);
});*/

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: "Bilgiler eksik!" });
    }

    const query = `
      SELECT 
        u.userID, 
        u.username, 
        u.password, 
        u.permission,
        ud.email, 
        ud.tel, 
        ud.cityID, 
        ud.address, 
        ud.job, 
        ud.warehouseID
      FROM user u
      LEFT JOIN userdata ud ON u.userID = ud.userID
      WHERE u.username = ?
      LIMIT 1
    `;

    const [rows] = await con.promise().query(query, [username]);

    if (rows.length === 0) {
      return res.status(401).json({ message: "Kullanici bulunamadi" });
    }

    const user = rows[0];

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Yanlis sifre" });
    }

    const sessionToken = uuidv4();

    await con.promise().query(
      "UPDATE user SET sessionToken = ? WHERE userID = ?",
      [sessionToken, user.userID]
    );

    const token = jwt.sign(
      {
        userID: user.userID,
        username: user.username,
        permission: user.permission,
        sessionToken
      },
      process.env.JWT_SECRET || "secretkey",
      { expiresIn: "7d" }
    );

    return res.status(200).json({
      message: "Giris basarili",
      token,
      user: {
        userID: user.userID,
        username: user.username,
        email: user.email,
        tel: user.tel,
        cityID: user.cityID,
        address: user.address,
        job: user.job,
        warehouseID: user.warehouseID
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    return res.status(500).json({ message: "Sunucu hatasi" });
  }
});


app.post('/logout', auth, async (req, res) => {
  try {
    await con.promise().query(
      "UPDATE user SET sessionToken = NULL WHERE userID = ?",
      [req.user.userID]
    );

    return res.status(200).json({
      message: "Cikis basarili"
    });

  } catch (err) {
    console.error("Logout error:", err);
    return res.status(500).json({
      message: "Sunucu hatasi"
    });
  }
});


app.get('/getCountries', auth, perm(1,2),
async(req, res) => {
  try{
    const query = 'select * from countries';
    const [result] = await con.promise().query(query);
    if(result.length ===0)
    {
      return res.status(200).json({message: "Sistemde Henüz Ülke Yok"})
    }
    return res.status(200).json(result)
  }
  catch (error)
  {
    return res.status(500).json({message: error.message});
  }
});

app.get('/getCities', auth, perm(1, 2), async (req, res) => {
  const id = req.query.id || '';
  try {
    if(!id)
    return res.status(400).json({message: "Bu işlem sadece ID ile çalışır => /getCities?id=1"});
    const query = 'select * from cities where cities.countryID = ?';
    const [results] = await con.promise().query(query, [id]);
    if(!results[0])
    {
      return res.status(200).json({message: "Belirttiğin ID'ye kayıtlı şehir yok."});
    }
    return res.status(200).json(results);
  }
  catch (error) {
    return res.status(500).json({message: error.message});
  }

})

app.get('/getUsers', auth, perm(1, 2), async (req, res) => {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.min(parseInt(req.query.limit) || 10, 100);
    const offset = (page - 1) * limit;

    const {
        username,
        email,
        cityID,
        warehouseID,
        job,
        sortBy = "userID",
        sortOrder = "DESC"
    } = req.query;

    const allowedSortFields = [
        "userID",
        "username",
        "email",
        "cityID",
        "warehouseID"
    ];

    const orderBy = allowedSortFields.includes(sortBy) ? sortBy : "userID";
    const orderDir = sortOrder.toUpperCase() === "ASC" ? "ASC" : "DESC";

    let where = [];
    let params = [];
    where.push("u.userID != ?");
    params.push(req.user.userID);

    if (username) {
        where.push("u.username LIKE ?");
        params.push(`%${username}%`);
    }

    if (email) {
        where.push("ud.email LIKE ?");
        params.push(`%${email}%`);
    }

    if (cityID) {
        where.push("ud.cityID = ?");
        params.push(cityID);
    }

    if (warehouseID) {
        where.push("ud.warehouseID = ?");
        params.push(warehouseID);
    }

    if (job) {
        where.push("ud.job LIKE ?");
        params.push(`%${job}%`);
    }

    const whereSQL = where.length ? `WHERE ${where.join(" AND ")}` : "";

    const dataQuery = `
        SELECT 
            u.userID, 
            u.username, 
            ud.email, 
            ud.tel, 
            ud.address, 
            ud.job, 
            ud.cityID, 
            ud.warehouseID
        FROM user u
        LEFT JOIN userdata ud ON u.userID = ud.userID
        ${whereSQL}
        ORDER BY ${orderBy} ${orderDir}
        LIMIT ? OFFSET ?
    `;

    const countQuery = `
        SELECT COUNT(*) AS total
        FROM user u
        LEFT JOIN userdata ud ON u.userID = ud.userID
        ${whereSQL}
    `;

    try {
        const [[{ total }]] = await con.promise().query(countQuery, params);
        const [results] = await con.promise().query(dataQuery, [...params, limit, offset]);

        if (results.length === 0) {
            return res.status(404).json({ message: "Kullanıcı bulunamadı." });
        }

        res.status(200).json({
            page,
            limit,
            total,
            totalPages: Math.ceil(total / limit),
            filters: req.query,
            data: results
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Veritabanı hatası." });
    }
});




app.post('/addUser', auth, perm(1), async (req, res) => {
  let {
    username,
    password,
    permission,
    email,
    tel,
    cityID,
    address,
    job,
    warehouseID
  } = req.body;

  if (
    !username ||
    !password ||
    !permission ||
    !email ||
    !tel ||
    !cityID ||
    !address ||
    !job ||
    !warehouseID
  ) {
    return res.status(400).json({ message: "Eksik alan girisi." });
  }

  if (username.length > 50) {
    return res
      .status(400)
      .json({ message: "Kullanici Adi 50 karakterden buyuk olamaz" });
  }
  if (password.length < 8 || password.length > 64) {
    return res.status(400).json({
      message: "Sifre en az 8, en fazla 64 karakter olmalidir"
    });
  }

  let hasUpperCase = false;
  let hasNumber = false;
  let hasSpecialChar = false;

  const specialChars = "!@#$%^&*()_+-=[]{}|;:'\",.<>?/`~";

  for (let i = 0; i < password.length; i++) {
    const char = password[i];

    if (char >= 'A' && char <= 'Z') {
      hasUpperCase = true;
    } else if (char >= '0' && char <= '9') {
      hasNumber = true;
    } else if (specialChars.includes(char)) {
      hasSpecialChar = true;
    }
  }

  if (!hasUpperCase) {
    return res.status(400).json({
      message: "Sifre en az 1 buyuk harf icermelidir"
    });
  }

  if (!hasNumber) {
    return res.status(400).json({
      message: "Sifre en az 1 rakam icermelidir"
    });
  }

  if (!hasSpecialChar) {
    return res.status(400).json({
      message: "Sifre en az 1 ozel karakter icermelidir"
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 12);

    let query =
      "INSERT INTO user (username, password, permission) VALUES (?, ?, ?)";
    let [result] = await con
      .promise()
      .query(query, [username, hashedPassword, permission]);

    const userID = result.insertId;

    query =
      "INSERT INTO userdata (userID, email, tel, cityID, address, job, warehouseID) VALUES (?, ?, ?, ?, ?, ?, ?)";
    await con
      .promise()
      .query(query, [userID, email, tel, cityID, address, job, warehouseID]);

    res.status(200).json({ message: "Islem Basarili" });
  } catch (error) {
    console.error("SQL Hatasi", error);
    return res.status(500).json({ error: "SQL Hatasi" });
  }
});



app.delete('/deleteUser', auth, perm(1), async (req, res) => {
  const id = req.query.userID;

  if (!id) {
    return res.status(400).json({ message: "UserID giriniz => /deleteUser?userID=1" });
  }

  if(id === req.user.userID)
  {
    return res.status(400).json({message: "Kendini silemezsin."})
  }

  try {
    const [search] = await con
      .promise()
      .query('SELECT COUNT(*) AS cnt FROM user WHERE userID = ?', [id]);

    if (search[0].cnt === 0) {
      return res
        .status(404)
        .json({ message: "Belirtilen UserID ile kayit bulunamadi." });
    }

    const connection = await con.promise().getConnection();

    try {
      await connection.beginTransaction();

      const [res1] = await connection.query(
        'DELETE FROM userdata WHERE userID = ?',
        [id]
      );

      if (res1.affectedRows === 0) {
        await connection.rollback();
        return res
          .status(400)
          .json({ message: "userdata silinirken hata olustu, islem geri alindi." });
      }

      const [res2] = await connection.query(
        'DELETE FROM user WHERE userID = ?',
        [id]
      );

      if (res2.affectedRows === 0) {
        await connection.rollback();
        return res
          .status(400)
          .json({ message: "user silinirken hata olustu, islem geri alindi." });
      }

      await connection.commit();
      return res
        .status(200)
        .json({ message: "Bilgiler basariyla silindi." });

    } catch (err) {
      await connection.rollback();
      console.error("SQL ERROR:", err);
      return res.status(500).json({
        message: "Veritabanı hatası oluştu.",
        sqlError: {
          code: err.code,
          errno: err.errno,
          sqlMessage: err.sqlMessage,
          sqlState: err.sqlState,
          sql: err.sql
        }
      });
    } finally {
      connection.release();
    }

  } catch (err) {
    console.error("SQL ERROR:", err);
    return res.status(500).json({ message: "Veritabanı hatası oluştu." });
  }
});


app.get('/getWH', auth, perm(1), async (req, res) => {
  const id = req.query.id || '';
  const name = req.query.name || '';
  const limit = 10;
  const pageNo = parseInt(req.query.pageNo) || 1;
  const offset = (pageNo - 1) * limit;

  const conditions = [];
  const params = [];

  if (id) {
    conditions.push("w.warehouseID = ?");
    params.push(id);
  }

  if (name) {
    conditions.push("w.warehouseName LIKE ?");
    params.push(`%${name}%`);
  }

  let whereClause = "";
  if (conditions.length > 0) {
    whereClause = " WHERE " + conditions.join(" AND ");
  }

  const dataQuery = `
      SELECT 
        w.warehouseID, 
        w.warehouseName, 
        w.warehouseAddress, 
        c.cityName, 
        co.countryName 
      FROM warehouse w
      LEFT JOIN cities c ON w.warehouseCityID = c.cityID
      LEFT JOIN countries co ON c.countryID = co.countryID
      ${whereClause}
      LIMIT ? OFFSET ?`;

  const countQuery = `SELECT COUNT(*) as total FROM warehouse w ${whereClause}`;

  try {
    const [rows] = await con.promise().query(dataQuery, [...params, limit, offset]);
    const [countResult] = await con.promise().query(countQuery, params);

    const total = countResult[0].total;
    const totalPages = Math.ceil(total / limit);

    if (rows.length === 0 && pageNo === 1) {
       return res.status(404).json({message: "Hicbir depo kaydi bulunamadi."});
    }

    return res.status(200).json({
      success: true,
      page: pageNo,
      limit: limit,
      total: total,
      totalPages: totalPages,
      data: rows
    });

  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.post('/addWH', auth, perm(1), async (req, res) => {
  const { warehouseName, warehouseCityID, warehouseAddress } = req.body;

  if (!warehouseCityID)
    return res.status(400).json({message: "WarehouseCityID girilmesi zorunludur."});

  const query = `INSERT INTO warehouse (warehouseName, warehouseCityID, warehouseAddress) VALUES (?, ?, ?)`;

  try {
    const [result] = await con.promise().query(query, [warehouseName, warehouseCityID, warehouseAddress]);
    return res.status(201).json({message: "Depo basariyla eklendi.", id: result.insertId});
  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.put('/editWH', auth, perm(1), async (req, res) => {
  const id = req.query.id;
  const { warehouseName, warehouseCityID, warehouseAddress } = req.body;

  if (!id)
    return res.status(400).json({message: "ID giriniz => /editWH?id=1"});

  const [search] = await con.promise().query('select count(*) as cnt from warehouse where warehouseID=?', [id]);

  if (search[0].cnt === 0)
    return res.status(404).json({message: "Belirtilen ID ile depo bulunamadi."});

  const query = `UPDATE warehouse SET warehouseName = ?, warehouseCityID = ?, warehouseAddress = ? WHERE warehouseID = ?`;

  try {
    await con.promise().query(query, [warehouseName, warehouseCityID, warehouseAddress, id]);
    return res.status(200).json({message: "Depo bilgileri guncellendi."});
  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.delete('/deleteWH', auth, perm(1), async (req, res) => {
  const id = req.query.id;

  if (!id)
    return res.status(400).json({message: "ID giriniz => /deleteWH?id=1"});

  const [search] = await con.promise().query('select count(*) as cnt from warehouse where warehouseID=?', [id]);

  if (search[0].cnt === 0)
    return res.status(404).json({message: "Belirtilen ID ile depo bulunamadi."});

  const query = `DELETE FROM warehouse WHERE warehouseID = ?`;

  try {
    await con.promise().query(query, [id]);
    return res.status(200).json({message: "Depo basariyla silindi."});
  } catch (err) {
    console.log(err);
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(400).json({message: "Bu depoda urunler veya kullanicilar kayitli oldugu icin silinemez."});
    }
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.post('/addTruck', auth, perm(1), async (req, res) => {
  const { truckBrand, truckModel } = req.body;

  const query = `INSERT INTO trucks (truckBrand, truckModel) VALUES (?, ?)`;

  try {
    const [result] = await con.promise().query(query, [truckBrand, truckModel]);
    return res.status(201).json({message: "Kamyon basariyla eklendi.", id: result.insertId});
  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.delete('/removeTruck', auth, perm(1), async (req, res) => {
  const id = req.query.id;

  if (!id)
    return res.status(400).json({message: "ID giriniz => /removeTruck?id=1"});

  const [search] = await con.promise().query('select count(*) as cnt from trucks where truckID=?', [id]);

  if (search[0].cnt === 0)
    return res.status(404).json({message: "Belirtilen ID ile kamyon bulunamadi."});

  const query = `DELETE FROM trucks WHERE truckID = ?`;

  try {
    await con.promise().query(query, [id]);
    return res.status(200).json({message: "Kamyon basariyla silindi."});
  } catch (err) {
    console.log(err);
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(400).json({message: "Bu kamyon modeli sisteme kayitli bir araca (TruckInfo) bagli oldugu icin silinemez."});
    }
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.get('/listTrucks', auth, perm(1, 2), async (req, res) => {
  const query = `SELECT * FROM trucks`;

  try {
    const [results] = await con.promise().query(query);
    res.status(200).json(results);
  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.post('/addTruckInfo', auth, perm(1), async (req, res) => {
  const { plate, truckID } = req.body;

  if (!plate || !truckID)
    return res.status(400).json({message: "Plaka ve TruckID girilmesi zorunludur."});

  const query = `INSERT INTO truckinfo (plate, truckID) VALUES (?, ?)`;

  try {
    const [result] = await con.promise().query(query, [plate, truckID]);
    return res.status(201).json({message: "Arac bilgisi basariyla eklendi.", id: result.insertId});
  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.put('/editTruckInfo', auth, perm(1), async (req, res) => {
  const id = req.query.id;
  const { plate, truckID } = req.body;

  if (!id)
    return res.status(400).json({message: "ID giriniz => /editTruckInfo?id=1"});

  const [search] = await con.promise().query('select count(*) as cnt from truckinfo where truckInfoID=?', [id]);

  if (search[0].cnt === 0)
    return res.status(404).json({message: "Belirtilen ID ile arac bulunamadi."});

  const query = `UPDATE truckinfo SET plate = ?, truckID = ? WHERE truckInfoID = ?`;

  try {
    await con.promise().query(query, [plate, truckID, id]);
    return res.status(200).json({message: "Arac bilgileri guncellendi."});
  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.delete('/removeTruckInfo', auth, perm(1), async (req, res) => {
  const id = req.query.id;

  if (!id)
    return res.status(400).json({message: "ID giriniz => /removeTruckInfo?id=1"});

  const [search] = await con.promise().query('select count(*) as cnt from truckinfo where truckInfoID=?', [id]);

  if (search[0].cnt === 0)
    return res.status(404).json({message: "Belirtilen ID ile arac bulunamadi."});

  const query = `DELETE FROM truckinfo WHERE truckInfoID = ?`;

  try {
    await con.promise().query(query, [id]);
    return res.status(200).json({message: "Arac basariyla silindi."});
  } catch (err) {
    console.log(err);
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(400).json({message: "Bu arac bir kombinasyonda (Combination) kullanildigi icin silinemez."});
    }
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.get('/listTruckInfo', auth, perm(1, 2), async (req, res) => {
  const query = `
    SELECT 
      ti.truckInfoID, 
      ti.plate, 
      t.truckBrand, 
      t.truckModel 
    FROM truckinfo ti
    LEFT JOIN trucks t ON ti.truckID = t.truckID
  `;

  try {
    const [results] = await con.promise().query(query);
    res.status(200).json(results);
  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});

app.post('/addProduct', auth, perm(1), async (req, res) => {
  const { productShape, weight, dimensionX, dimensionY, dimensionZ, isBreakable, sender, warehouse } = req.body;

  if (!warehouse) return res.status(400).json({ message: "Warehouse ID girilmesi zorunludur." });

  const connection = await con.promise().getConnection();

  try {
    await connection.beginTransaction();

    const [statusResult] = await connection.query(
      "INSERT INTO status (statusType, statusDate) VALUES (?, NOW())", 
      [1]
    );
    const newStatusID = statusResult.insertId;

    const [productResult] = await connection.query(
      `INSERT INTO product (productShape, weight, dimensionX, dimensionY, dimensionZ, isBreakable, statusID, sender, dateReceived, warehouse) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)`,
      [productShape, weight, dimensionX, dimensionY, dimensionZ, isBreakable, newStatusID, sender, warehouse]
    );

    await connection.commit();
    res.status(201).json({ message: "Urun ve baslangic statüsü basariyla eklendi.", id: productResult.insertId });
  } catch (err) {
    await connection.rollback();
    console.error(err);
    res.status(500).json({ error: "Veritabani hatasi." });
  } finally {
    connection.release();
  }
});

app.put('/editProduct', auth, perm(1), async (req, res) => {
  const id = req.query.id;
  const { productShape, weight, dimensionX, dimensionY, dimensionZ, isBreakable, sender, warehouse } = req.body;

  if (!id) return res.status(400).json({ message: "ID giriniz." });

  const query = `
    UPDATE product 
    SET productShape=?, weight=?, dimensionX=?, dimensionY=?, dimensionZ=?, isBreakable=?, sender=?, warehouse=? 
    WHERE productID=?`;

  try {
    const [result] = await con.promise().query(query, [productShape, weight, dimensionX, dimensionY, dimensionZ, isBreakable, sender, warehouse, id]);
    if (result.affectedRows === 0) return res.status(404).json({ message: "Urun bulunamadi." });
    res.status(200).json({ message: "Urun bilgileri guncellendi." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Veritabani hatasi." });
  }
});

app.get('/listProducts', auth, perm(1, 2), async (req, res) => {
  const query = `
    SELECT 
      p.*, 
      w.warehouseName,
      st.statusName,
      s.statusDate
    FROM product p
    LEFT JOIN warehouse w ON p.warehouse = w.warehouseID
    LEFT JOIN status s ON p.statusID = s.statusID
    LEFT JOIN statustype st ON s.statusType = st.statusTypeID
  `;

  try {
    const [results] = await con.promise().query(query);
    res.status(200).json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Veritabani hatasi." });
  }
});

app.use((req, res) => {
  res.status(404).json({message: "Bu API bulunmuyor."})
});
