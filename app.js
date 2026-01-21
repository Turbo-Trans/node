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
app.listen(PORT, async () => {
  console.log(`Node sunucusu ${PORT} portunda baslatildi.`);
  /*try {
    const [result] = await con.promise().query("UPDATE user SET sessionToken = NULL");
  } catch (err) {
    console.error("SYSTEM ERROR", err);
  }*/
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
      { expiresIn: "30d" }
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
  let uQuery = 'SELECT u.username FROM user u WHERE u.username = ?';
  [usernameQuery] = await con.promise().query(uQuery, [username]);

  if(usernameQuery.length > 0)
  {
    return res.status(400).json({ message: "Var olan Username giremezsiniz!"});
  }

  uQuery = 'SELECT ud.email FROM userdata ud JOIN user u ON ud.userID = u.userID WHERE ud.email = ?'
  const [emailQuery] = await con.promise().query(uQuery, [email]);
  if(emailQuery.length > 0)
  {
    return res.status(400).json({ message: "Var olan email giremezsiniz!"});
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

  const hasUpperCase = /[\p{Lu}]/u.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~]/.test(password);

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
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const { truckBrand, truckModel } = req.query;

    let whereConditions = [];
    let queryParams = [];

    if (truckBrand) {
      whereConditions.push("truckBrand LIKE ?");
      queryParams.push(`%${truckBrand}%`);
    }

    if (truckModel) {
      whereConditions.push("truckModel LIKE ?");
      queryParams.push(`%${truckModel}%`);
    }

    let whereClause = "";
    if (whereConditions.length > 0) {
      whereClause = " WHERE " + whereConditions.join(" AND ");
    }

    const countQuery = `SELECT COUNT(*) as total FROM trucks` + whereClause;
    const [countResult] = await con.promise().query(countQuery, queryParams);
    const totalItems = countResult[0].total;

    const dataQuery = `SELECT * FROM trucks` + whereClause + ` LIMIT ? OFFSET ?`;
    const dataParams = [...queryParams, limit, offset];
    
    const [results] = await con.promise().query(dataQuery, dataParams);

    res.status(200).json({
      data: results,
      pagination: {
        totalItems,
        totalPages: Math.ceil(totalItems / limit),
        currentPage: page,
        itemsPerPage: limit
      }
    });

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
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const { plate, truckBrand, truckModel } = req.query;

    let whereConditions = [];
    let queryParams = [];

    if (plate) {
      whereConditions.push("ti.plate LIKE ?");
      queryParams.push(`%${plate}%`);
    }

    if (truckBrand) {
      whereConditions.push("t.truckBrand LIKE ?");
      queryParams.push(`%${truckBrand}%`);
    }

    if (truckModel) {
      whereConditions.push("t.truckModel LIKE ?");
      queryParams.push(`%${truckModel}%`);
    }

    let whereClause = "";
    if (whereConditions.length > 0) {
      whereClause = " WHERE " + whereConditions.join(" AND ");
    }

    const countQuery = `
      SELECT COUNT(*) as total 
      FROM truckinfo ti 
      LEFT JOIN trucks t ON ti.truckID = t.truckID
    ` + whereClause;

    const [countResult] = await con.promise().query(countQuery, queryParams);
    const totalItems = countResult[0].total;

    const dataQuery = `
      SELECT 
        ti.truckInfoID, 
        ti.plate, 
        t.truckBrand, 
        t.truckModel 
      FROM truckinfo ti
      LEFT JOIN trucks t ON ti.truckID = t.truckID
      ${whereClause}
      LIMIT ? OFFSET ?
    `;

    const dataParams = [...queryParams, limit, offset];
    
    const [results] = await con.promise().query(dataQuery, dataParams);

    res.status(200).json({
      data: results,
      pagination: {
        totalItems,
        totalPages: Math.ceil(totalItems / limit),
        currentPage: page,
        itemsPerPage: limit
      }
    });

  } catch (err) {
    console.log(err);
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});



app.get('/listProducts', auth, perm(1, 2), async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const offset = (page - 1) * limit;

    const {
      id,
      shape,
      sender,
      date,
      breakable,
      status
    } = req.query;

    const userID = req.user.userID;
    const [uid] = await con
      .promise()
      .query('SELECT warehouseID FROM userdata WHERE userID = ?', [userID]);

    const warehouseID = uid[0]?.warehouseID;

    if (!warehouseID) {
      return res.status(403).json({ message: 'Depoda çalışmıyorsun!' });
    }

    let whereConditions = ['product.warehouse = ?'];
    let params = [warehouseID];

    if (id) {
      whereConditions.push('product.productID LIKE ?');
      params.push(`%${id}%`);
    }

    if (shape) {
      whereConditions.push('product.productShape LIKE ?');
      params.push(`%${shape}%`);
    }

    if (sender) {
      whereConditions.push('product.sender LIKE ?');
      params.push(`%${sender}%`);
    }

    if (date) {
      whereConditions.push('DATE(product.dateReceived) = ?');
      params.push(date);
    }

    if (breakable) {
      whereConditions.push('product.isBreakable = ?');
      params.push(breakable);
    }

    if (status) {
      whereConditions.push('status.statusType = ?');
      params.push(status);
    }

    const whereClause = `WHERE ${whereConditions.join(' AND ')}`;

    const dataQuery = `
      SELECT 
        product.*, 
        statustype.statusName,
        status.statusDate,
        status.statusType
      FROM product
      LEFT JOIN status ON product.statusID = status.statusID
      LEFT JOIN statustype ON status.statusType = statustype.statusTypeID
      ${whereClause}
      ORDER BY product.dateReceived DESC
      LIMIT ? OFFSET ?
    `;

    const [rows] = await con
      .promise()
      .query(dataQuery, [...params, limit, offset]);

    const countQuery = `
      SELECT COUNT(*) AS total
      FROM product
      LEFT JOIN status ON product.statusID = status.statusID
      ${whereClause}
    `;

    const [[{ total }]] = await con
      .promise()
      .query(countQuery, params);

    res.json({
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      data: rows
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'SQL hatasi' });
  }
});

app.post('/addProduct', auth, perm(1, 2), async (req, res) => {
  const {
    productShape,
    sender,
    isBreakable,
    weight,
    dimensionX,
    dimensionY,
    dimensionZ
  } = req.body;

  if (!productShape || !sender) {
    return res.status(400).json({ message: "Eksik alan girisi." });
  }

  try {
    const connection = await con.promise().getConnection();
    await connection.beginTransaction();

    const [userWH] = await connection.query(
      'SELECT warehouseID FROM userdata WHERE userID = ?',
      [req.user.userID]
    );

    if (!userWH[0]?.warehouseID) {
      await connection.rollback();
      return res.status(403).json({ message: "Depo bilgin bulunamadi." });
    }

    const warehouseID = userWH[0].warehouseID;

    const [statusResult] = await connection.query(
      'INSERT INTO status (statusType, statusDate) VALUES (1, NOW())'
    );
    const newStatusID = statusResult.insertId;

    const insertQuery = `
      INSERT INTO product 
      (productShape, sender, isBreakable, weight, dimensionX, dimensionY, dimensionZ, warehouse, statusID, dateReceived)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
    `;

    const [productResult] = await connection.query(insertQuery, [
      productShape,
      sender,
      isBreakable || 0,
      weight || 0,
      dimensionX || 0,
      dimensionY || 0,
      dimensionZ || 0,
      warehouseID,
      newStatusID
    ]);

    await connection.commit();
    connection.release();

    return res.status(201).json({
      message: "Urun basariyla eklendi.",
      productID: productResult.insertId
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Veritabani hatasi." });
  }
});

app.put('/editProduct', auth, perm(1, 2), async (req, res) => {
  const id = req.query.id;
  if (!id) {
    return res.status(400).json({ message: "ID giriniz => /editProduct?id=1" });
  }

  let connection;

  try {
    const [userWH] = await con.promise().query(
      'SELECT warehouseID FROM userdata WHERE userID = ?',
      [req.user.userID]
    );

    connection = await con.promise().getConnection();
    await connection.beginTransaction();

    const [search] = await connection.query(
      `SELECT warehouse, statusID 
       FROM product 
       WHERE productID = ? 
       FOR UPDATE`,
      [id]
    );

    if (!search[0]) {
      await connection.rollback();
      connection.release();
      return res.status(404).json({ message: "Urun bulunamadi." });
    }

    if (search[0].warehouse !== userWH[0]?.warehouseID) {
      await connection.rollback();
      connection.release();
      return res.status(403).json({ message: "Bu urunu guncelleyemezsin." });
    }

    await connection.query(
      `UPDATE product SET
        productShape = ?,
        sender = ?,
        isBreakable = ?,
        weight = ?,
        dimensionX = ?,
        dimensionY = ?,
        dimensionZ = ?
       WHERE productID = ?`,
      [
        productShape,
        sender,
        isBreakable,
        weight,
        dimensionX,
        dimensionY,
        dimensionZ,
        id
      ]
    );

    if (statusID) {
      await connection.query(
        'UPDATE status SET statusType = ?, statusDate = NOW() WHERE statusID = ?',
        [statusID, search[0].statusID]
      );
    }

    await connection.commit();
    connection.release();

    return res.status(200).json({ message: "Urun guncellendi." });

  } catch (err) {
    if (connection) {
      await connection.rollback();
      connection.release();
    }
    console.error(err);
    return res.status(500).json({ message: "Veritabani hatasi." });
  }
});


app.delete('/deleteProduct', auth, perm(1,2), async (req, res) => {
  const id = req.query.id;

  if (!id) {
    return res.status(400).json({ message: "ID giriniz => /deleteProduct?id=1" });
  }

  try {
    const connection = await con.promise().getConnection();
    await connection.beginTransaction();

    const [search] = await connection.query(
      'SELECT productID, statusID FROM product WHERE productID = ?',
      [id]
    );

    if (!search[0]) {
      await connection.rollback();
      return res.status(404).json({ message: "Urun bulunamadi." });
    }

    const statusRowID = search[0].statusID;

    await connection.query(
      'DELETE FROM product WHERE productID = ?',
      [id]
    );

    if (statusRowID) {
      await connection.query(
        'DELETE FROM status WHERE statusID = ?',
        [statusRowID]
      );
    }

    await connection.commit();
    connection.release();

    return res.status(200).json({ message: "Urun basariyla silindi." });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Veritabani hatasi." });
  }
});

app.get('/listProductShapes', auth, perm(1, 2), async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(parseInt(req.query.limit) || 10, 1);
    const offset = (page - 1) * limit;

    const countQuery = `SELECT COUNT(*) as total FROM productshape`;
    const [countResult] = await con.promise().query(countQuery);
    const total = countResult[0].total;

    const dataQuery = `
      SELECT * FROM productshape 
      ORDER BY shapeID ASC 
      LIMIT ? OFFSET ?
    `;
    
    const [rows] = await con.promise().query(dataQuery, [limit, offset]);

    res.status(200).json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      data: rows
    });

  } catch (err) {
    console.error("List ProductShapes Error:", err);
    return res.status(500).json({ error: "Veritabanı hatası." });
  }
});

app.post('/createOrder', auth, perm(1, 2), async (req, res) => {
  const { 
    receiverID, 
    productIDs, 
    truckInfoID, 
    trailerID, 
    kingPinOffset, 
    kingPinLimit 
  } = req.body;

  if (
    !receiverID || 
    !truckInfoID || 
    !trailerID || 
    !productIDs || 
    !Array.isArray(productIDs) || 
    productIDs.length === 0
  ) {
    return res.status(400).json({ message: "Eksik bilgi: Alıcı, Araç (TruckInfo), Dorse (Trailer) ve Ürün listesi zorunludur." });
  }

  const connection = await con.promise().getConnection();

  try {
    await connection.beginTransaction();

    const [userCheck] = await connection.query(
      'SELECT warehouseID FROM userdata WHERE userID = ?',
      [req.user.userID]
    );

    if (!userCheck[0] || !userCheck[0].warehouseID) {
      await connection.rollback();
      return res.status(403).json({ message: "Bir depoya atanmamışsınız, işlem yapamazsınız." });
    }

    const userWarehouseID = userCheck[0].warehouseID;

    const [receiverCheck] = await connection.query(
      'SELECT count(*) as cnt FROM receiver WHERE receiverID = ?',
      [receiverID]
    );

    if (receiverCheck[0].cnt === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "Alıcı bulunamadı." });
    }

    const [truckCheck] = await connection.query(
      'SELECT count(*) as cnt FROM truckinfo WHERE truckInfoID = ?',
      [truckInfoID]
    );

    if (truckCheck[0].cnt === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "Belirtilen Araç (TruckInfo) bulunamadı." });
    }

    const [trailerCheck] = await connection.query(
      'SELECT count(*) as cnt FROM trailer WHERE trailerID = ?',
      [trailerID]
    );

    if (trailerCheck[0].cnt === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "Belirtilen Dorse (Trailer) bulunamadı." });
    }

    const [validProducts] = await connection.query(`
      SELECT 
        p.productID, 
        p.warehouse, 
        p.statusID,
        s.statusType 
      FROM product p
      LEFT JOIN status s ON p.statusID = s.statusID
      WHERE p.productID IN (?) AND s.active = 1
    `, [productIDs]);

    if (validProducts.length !== productIDs.length) {
      await connection.rollback();
      return res.status(400).json({ message: "Bazı ürünler bulunamadı veya aktif değil." });
    }

    for (const prod of validProducts) {
      if (prod.warehouse !== userWarehouseID) {
        await connection.rollback();
        return res.status(403).json({ message: `Ürün ID: ${prod.productID} sizin deponuzda değil.` });
      }

      if (prod.statusType !== 1) {
        await connection.rollback();
        return res.status(400).json({ message: `Ürün ID: ${prod.productID} gönderilmeye uygun statüsünde değil (StatusType: ${prod.statusType}).` });
      }
    }

    const [combResult] = await connection.query(
      'INSERT INTO combination (truckInfoID, trailerID, kingpinoffset, kingpinlimit) VALUES (?, ?, ?, ?)',
      [truckInfoID, trailerID, kingPinOffset || 0, kingPinLimit || 0]
    );
    const newCombinationID = combResult.insertId;

    // Format: #xyzab (Year|Month|Day|Hour|Minutes|Seconds|UserID)
    const now = new Date();
    const x = now.getFullYear();
    const y = now.getMonth() + 1; 
    const z = now.getDate();
    const s = now.getSeconds();
    const b = req.user.userID;
    const m = now.getMinutes();
    const h = now.getHours();
    
    const orderNumber = `#${x}-${y}-${z}-${h}-${m}-${s}-${b}`;

    const [orderResult] = await connection.query(
      'INSERT INTO orders (orderNumber, receiverID) VALUES (?, ?)',
      [orderNumber, receiverID]
    );
    const newOrderID = orderResult.insertId;

    for (const prod of validProducts) {
      await connection.query(
        'UPDATE status SET active = 0 WHERE statusID = ?',
        [prod.statusID]
      );

      const [newStatusResult] = await connection.query(
        'INSERT INTO status (statusType, statusDate, active) VALUES (2, NOW(), 1)'
      );
      const newStatusID = newStatusResult.insertId;

      await connection.query(
        'UPDATE product SET statusID = ?, orderID = ? WHERE productID = ?',
        [newStatusID, newOrderID, prod.productID]
      );
    }

    const [itineraryResult] = await connection.query(
      'INSERT INTO itinerary (orderID, combinationID, active) VALUES (?, ?, 1)',
      [newOrderID, newCombinationID]
    );

    await connection.commit();
    return res.status(201).json({
      message: "Sipariş, Kombinasyon ve Yolculuk planı başarıyla oluşturuldu.",
      orderID: newOrderID,
      orderNumber: orderNumber,
      combinationID: newCombinationID,
      itineraryID: itineraryResult.insertId
    });

  } catch (err) {
    await connection.rollback();
    console.error(err);
    return res.status(500).json({ message: "Veritabanı hatası." });
  } finally {
    connection.release();
  }
});

app.get('/listOrders', auth, perm(1, 2), async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(parseInt(req.query.limit) || 10, 1);
    const offset = (page - 1) * limit;

    const {
      orderNumber,
      receiverName,
      active
    } = req.query;

    const userID = req.user.userID;
    const [userCheck] = await con.promise().query(
      'SELECT warehouseID FROM userdata WHERE userID = ?', 
      [userID]
    );

    const warehouseID = userCheck[0]?.warehouseID;

    if (!warehouseID) {
      return res.status(403).json({ message: 'Bir depoya atanmamışsınız, siparişleri görüntüleyemezsiniz.' });
    }

    let whereConditions = ['p.warehouse = ?'];
    let params = [warehouseID];

    if (orderNumber) {
      whereConditions.push('o.orderNumber LIKE ?');
      params.push(`%${orderNumber}%`);
    }

    if (receiverName) {
      whereConditions.push('r.receiverName LIKE ?');
      params.push(`%${receiverName}%`);
    }

    if (active !== undefined) {
      whereConditions.push('i.active = ?');
      params.push(active);
    }

    const whereClause = `WHERE ${whereConditions.join(' AND ')}`;

    const countQuery = `
      SELECT COUNT(DISTINCT o.orderID) as total
      FROM orders o
      JOIN product p ON o.orderID = p.orderID
      LEFT JOIN receiver r ON o.receiverID = r.receiverID
      LEFT JOIN itinerary i ON o.orderID = i.orderID
      ${whereClause}
    `;

    const [[{ total }]] = await con.promise().query(countQuery, params);

    const dataQuery = `
      SELECT 
        o.orderID,
        o.orderNumber,
        r.receiverName,
        r.receiverAddress,
        c.cityName as receiverCity,
        co.countryName as receiverCountry,
        COUNT(DISTINCT p.productID) as productCount,
        i.active as itineraryActive
      FROM orders o
      JOIN product p ON o.orderID = p.orderID
      LEFT JOIN receiver r ON o.receiverID = r.receiverID
      LEFT JOIN cities c ON r.receiverCityID = c.cityID
      LEFT JOIN countries co ON c.countryID = co.countryID
      LEFT JOIN itinerary i ON o.orderID = i.orderID
      ${whereClause}
      GROUP BY o.orderID, i.active
      ORDER BY o.orderID DESC
      LIMIT ? OFFSET ?
    `;

    const [rows] = await con.promise().query(dataQuery, [...params, limit, offset]);

    res.status(200).json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      data: rows
    });

  } catch (err) {
    console.error("List Orders Error:", err);
    res.status(500).json({ message: 'Veritabanı hatası oluştu.' });
  }
});


app.get('/orderDetails', auth, perm(1, 2), async (req, res) => {
  const { orderID } = req.query;

  if (!orderID) {
    return res.status(400).json({ message: "OrderID giriniz => /orderDetails?orderID=..." });
  }

  try {
    const [userCheck] = await con.promise().query(
      'SELECT warehouseID FROM userdata WHERE userID = ?',
      [req.user.userID]
    );
    const warehouseID = userCheck[0]?.warehouseID;

    if (!warehouseID) {
      return res.status(403).json({ message: 'Bir depoya atanmamışsınız.' });
    }

    const [permCheck] = await con.promise().query(
      'SELECT 1 FROM product WHERE orderID = ? AND warehouse = ? LIMIT 1',
      [orderID, warehouseID]
    );

    if (permCheck.length === 0) {
      return res.status(403).json({ message: "Bu siparişe erişim izniniz yok veya sipariş bulunamadı." });
    }

    const queryDetails = `
      SELECT 
        o.orderID, o.orderNumber,
        r.receiverName, r.receiverAddress, 
        c.cityName as receiverCity, co.countryName as receiverCountry,
        i.itineraryID, i.active as itineraryActive,
        comb.combinationID, comb.kingpinoffset, comb.kingpinlimit,
        ti.plate, 
        t.truckBrand, t.truckModel,
        tr.dimensionX as trailerDimX, tr.dimensionY as trailerDimY, tr.dimensionZ as trailerDimZ,
        tr.wlimit as trailerWLimit, tr.axis_d
      FROM orders o
      LEFT JOIN receiver r ON o.receiverID = r.receiverID
      LEFT JOIN cities c ON r.receiverCityID = c.cityID
      LEFT JOIN countries co ON c.countryID = co.countryID
      LEFT JOIN itinerary i ON o.orderID = i.orderID
      LEFT JOIN combination comb ON i.combinationID = comb.combinationID
      LEFT JOIN truckinfo ti ON comb.truckInfoID = ti.truckInfoID
      LEFT JOIN trucks t ON ti.truckID = t.truckID
      LEFT JOIN trailer tr ON comb.trailerID = tr.trailerID
      WHERE o.orderID = ?
    `;

    const [details] = await con.promise().query(queryDetails, [orderID]);

    if (details.length === 0) {
      return res.status(404).json({ message: "Sipariş detayları bulunamadı." });
    }

    const d = details[0];

    const responseData = {
      orderInfo: {
        orderID: d.orderID,
        orderNumber: d.orderNumber
      },
      receiverInfo: {
        name: d.receiverName,
        address: d.receiverAddress,
        city: d.receiverCity,
        country: d.receiverCountry
      },
      itineraryInfo: {
        itineraryID: d.itineraryID,
        active: d.itineraryActive === 1
      },
      combinationInfo: {
        combinationID: d.combinationID,
        kingPinOffset: d.kingpinoffset,
        kingPinLimit: d.kingpinlimit,
        truck: {
          plate: d.plate,
          brand: d.truckBrand,
          model: d.truckModel
        },
        trailer: {
          dimensions: {
            x: d.trailerDimX,
            y: d.trailerDimY,
            z: d.trailerDimZ
          },
          weightLimit: d.trailerWLimit,
          axisDistance: d.axis_d
        }
      }
    };

    return res.status(200).json(responseData);

  } catch (err) {
    console.error("Order Details Error:", err);
    return res.status(500).json({ message: "Veritabanı hatası oluştu." });
  }
});

app.delete('/deleteOrder', auth, perm(1, 2), async (req, res) => {
  const { orderID } = req.query;

  if (!orderID) {
    return res.status(400).json({ message: "OrderID giriniz => /deleteOrder?orderID=..." });
  }

  try {
    const connection = await con.promise().getConnection();
    await connection.beginTransaction();

    const [userCheck] = await connection.query(
      'SELECT warehouseID FROM userdata WHERE userID = ?',
      [req.user.userID]
    );
    const warehouseID = userCheck[0]?.warehouseID;

    if (!warehouseID) {
      await connection.rollback();
      connection.release();
      return res.status(403).json({ message: 'Bir depoya atanmamışsınız.' });
    }

    const [permCheck] = await connection.query(
      'SELECT 1 FROM product WHERE orderID = ? AND warehouse = ? LIMIT 1',
      [orderID, warehouseID]
    );

    if (permCheck.length === 0) {
      await connection.rollback();
      connection.release();
      return res.status(403).json({ message: "Bu siparişi silme yetkiniz yok veya sipariş bulunamadı." });
    }

    const [result] = await connection.query(
      'UPDATE itinerary SET active = 0 WHERE orderID = ?',
      [orderID]
    );

    if (result.affectedRows === 0) {
      await connection.rollback();
      connection.release();
      return res.status(404).json({ message: "Sipariş için aktif bir yolculuk kaydı bulunamadı." });
    }

    await connection.commit();
    connection.release();

    return res.status(200).json({ message: "Sipariş başarıyla iptal edildi (Itinerary pasife alındı)." });

  } catch (err) {
    console.error("Delete Order Error:", err);
    return res.status(500).json({ message: "Veritabanı hatası oluştu." });
  }
});


app.post('/addTrailer', auth, perm(1), async (req, res) => {
  const { 
    dimensionX, 
    dimensionY, 
    dimensionZ, 
    axis_d, 
    wlimitBack, 
    wlimitFront, 
    wlimit 
  } = req.body;

  if (!dimensionX || !dimensionY || !dimensionZ || !wlimit) {
    return res.status(400).json({ message: "Boyutlar (X, Y, Z) ve ağırlık limiti (wlimit) zorunludur." });
  }

  const query = `
    INSERT INTO trailer 
    (dimensionX, dimensionY, dimensionZ, axis_d, wlimitBack, wlimitFront, wlimit) 
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;

  try {
    const [result] = await con.promise().query(query, [
      dimensionX, 
      dimensionY, 
      dimensionZ, 
      axis_d || 0, 
      wlimitBack || 0, 
      wlimitFront || 0, 
      wlimit
    ]);
    return res.status(201).json({ message: "Dorse başarıyla eklendi.", id: result.insertId });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Veritabanı hatası." });
  }
});

app.delete('/removeTrailer', auth, perm(1), async (req, res) => {
  const id = req.query.id;

  if (!id) {
    return res.status(400).json({ message: "ID giriniz => /removeTrailer?id=1" });
  }

  try {
    const [search] = await con.promise().query('SELECT count(*) as cnt FROM trailer WHERE trailerID = ?', [id]);

    if (search[0].cnt === 0) {
      return res.status(404).json({ message: "Belirtilen ID ile dorse bulunamadı." });
    }

    const query = `DELETE FROM trailer WHERE trailerID = ?`;
    await con.promise().query(query, [id]);
    
    return res.status(200).json({ message: "Dorse başarıyla silindi." });

  } catch (err) {
    console.error(err);
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(400).json({ message: "Bu dorse bir kombinasyonda (Combination) kullanıldığı için silinemez." });
    }
    return res.status(500).json({ error: "Veritabanı hatası." });
  }
});

app.get('/listTrailers', auth, perm(1, 2), async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(parseInt(req.query.limit) || 10, 1);
    const offset = (page - 1) * limit;

    const countQuery = `SELECT COUNT(*) as total FROM trailer`;
    const [countResult] = await con.promise().query(countQuery);
    const total = countResult[0].total;

    const dataQuery = `SELECT * FROM trailer ORDER BY trailerID DESC LIMIT ? OFFSET ?`;
    const [rows] = await con.promise().query(dataQuery, [limit, offset]);

    res.status(200).json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      data: rows
    });

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Veritabanı hatası." });
  }
});


app.post('/createReceiver', auth, perm(1, 2), async (req, res) => {
  const { receiverName, receiverCityID, receiverAddress } = req.body;

  if (!receiverName || !receiverCityID || !receiverAddress) {
    return res.status(400).json({ message: "Alıcı adı, Şehir ID ve Adres zorunludur." });
  }

  try {
    const [cityCheck] = await con.promise().query('SELECT 1 FROM cities WHERE cityID = ?', [receiverCityID]);
    if (cityCheck.length === 0) {
      return res.status(404).json({ message: "Geçersiz Şehir ID." });
    }

    const query = `
      INSERT INTO receiver (receiverName, receiverCityID, receiverAddress) 
      VALUES (?, ?, ?)
    `;

    const [result] = await con.promise().query(query, [receiverName, receiverCityID, receiverAddress]);
    
    return res.status(201).json({ 
      message: "Alıcı başarıyla oluşturuldu.", 
      receiverID: result.insertId 
    });

  } catch (err) {
    console.error("Create Receiver Error:", err);
    return res.status(500).json({ error: "Veritabanı hatası." });
  }
});

app.delete('/removeReceiver', auth, perm(1), async (req, res) => {
  const id = req.query.id;

  if (!id) {
    return res.status(400).json({ message: "ID giriniz => /removeReceiver?id=1" });
  }

  try {
    const [search] = await con.promise().query('SELECT count(*) as cnt FROM receiver WHERE receiverID = ?', [id]);

    if (search[0].cnt === 0) {
      return res.status(404).json({ message: "Alıcı bulunamadı." });
    }

    const query = `DELETE FROM receiver WHERE receiverID = ?`;
    await con.promise().query(query, [id]);

    return res.status(200).json({ message: "Alıcı başarıyla silindi." });

  } catch (err) {
    console.error("Remove Receiver Error:", err);
    
    if (err.code === 'ER_ROW_IS_REFERENCED_2') {
      return res.status(400).json({ message: "Bu alıcıya ait sipariş kayıtları bulunduğu için silinemez." });
    }
    
    return res.status(500).json({ error: "Veritabanı hatası." });
  }
});


app.get('/listReceivers', auth, perm(1, 2), async (req, res) => {
  try {
    const page = Math.max(parseInt(req.query.page) || 1, 1);
    const limit = Math.max(parseInt(req.query.limit) || 10, 1);
    const offset = (page - 1) * limit;

    const { name, city, country } = req.query;

    let whereConditions = [];
    let params = [];

    if (name) {
      whereConditions.push("r.receiverName LIKE ?");
      params.push(`%${name}%`);
    }

    if (city) {
      whereConditions.push("c.cityName LIKE ?");
      params.push(`%${city}%`);
    }

    if (country) {
      whereConditions.push("co.countryName LIKE ?");
      params.push(`%${country}%`);
    }

    let whereClause = "";
    if (whereConditions.length > 0) {
      whereClause = " WHERE " + whereConditions.join(" AND ");
    }

    const countQuery = `
      SELECT COUNT(*) as total 
      FROM receiver r
      LEFT JOIN cities c ON r.receiverCityID = c.cityID
      LEFT JOIN countries co ON c.countryID = co.countryID
      ${whereClause}
    `;
    
    const [[{ total }]] = await con.promise().query(countQuery, params);

    const dataQuery = `
      SELECT 
        r.receiverID, 
        r.receiverName, 
        r.receiverAddress, 
        c.cityID,
        c.cityName, 
        co.countryID,
        co.countryName
      FROM receiver r
      LEFT JOIN cities c ON r.receiverCityID = c.cityID
      LEFT JOIN countries co ON c.countryID = co.countryID
      ${whereClause}
      ORDER BY r.receiverID DESC
      LIMIT ? OFFSET ?
    `;

    const [rows] = await con.promise().query(dataQuery, [...params, limit, offset]);

    res.status(200).json({
      success: true,
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
      data: rows
    });

  } catch (err) {
    console.error("List Receivers Error:", err);
    return res.status(500).json({ error: "Veritabanı hatası." });
  }
});

app.use((req, res) => {
  res.status(404).json({message: "Bu API bulunmuyor."})
});
