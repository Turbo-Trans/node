const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require("jsonwebtoken");
const app = express();
var path = require("path");
const bcrypt = require("bcrypt");
const con = require("./components/db");
const auth = require('./components/auth');
const perm = require('./components/perm');


var regularExpression = /^(?=.*[0-9])(?=.*[!@#$%^&*])[a-zA-Z0-9!@#$%^&*]{8,64}$/;


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
      return res.status(400).json({ message: "Eksik bilgi girisi" });
    }

    const query = `
      SELECT u.userID, u.username, u.password, u.permission, ud.email, ud.tel, ud.cityID, ud.address, ud.job, ud.warehouseID
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

    const token = jwt.sign(
      { userID: user.userID, username: user.username , permission: user.permission},
      process.env.JWT_SECRET || "secretkey",
      { expiresIn: "7d" }
    );

    res.json({
      message: "Giris Basarili.",
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
    res.status(500).json({ message: "Sunucu hatasi" });
  }
});

app.get('/getUsers', auth, perm(1,2), 
  async(req,res) => 
  {
  const query = `select * from userData`;
  const [results] = await con.promise().query(query);
  res.json(results);
  }
);



app.post('/addUser', auth, perm(1),
  async(req,res) =>
  {
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


    if(!username || !password || !permission || !email || !tel || !cityID || !address || !job || !warehouseID)
    return res.status(400).json({message: "Eksik alan girisi."});

    if(username.length > 50)
    {
      return res.status(400).json({message: "Kullanici Adi 50 karakterden buyuk olamaz"});
    }

    if(!regularExpression.test(password))
    {
    return res.status(400).json({message: "En Az 8, En Fazla 64 Karakter. Bir Sayi ve Bir Ozel karakter icermeli"})}

    try {

      const hashedPassword = await bcrypt.hash("123456", 12);

      query = "insert into user(username,password,permission) values (?,?,?)";
      let [result] = await con.promise().query(query, [username,hashedPassword,permission]);
      const userID = result.insertId;
      query = "insert into userdata(userID,email,tel,cityID,address,job,warehouseID) values (?,?,?,?,?,?,?)";
      result = await con.promise().query(query,[userID,email,tel,cityID,address,job,warehouseID]);
      res.status(200).json({message: "Islem Basarili"});
    }
    catch (error) {
      console.error("SQL Hatasi", error);
      return res.status(500).json({error: "SQL Hatasi"})
    }
  }

);


app.delete('/deleteUser', auth, perm(1), async(req, res) => {
  const id = req.query.userID;
  if(!id)
  return res.status(400).json({message: "UserID giriniz => /deleteUser?userID=1"});

  const [search] = await con.promise().query('select count(*) as cnt from user where userID=?',[id]);

  if(search[0].cnt === 0)
  return res.status(404).json({message: "Belirtilen UserID ile kayit bulunamadi."});

  const query1 = `delete from userdata where userID = ?`;
  const query2 = `delete from users where userID = ?`;
  const connection = await con.promise().getConnection();

  try {
    await connection.beginTransaction();
    const [res1] = await connection.promise().query(query1,[id]);
    if(res1.affectedRows === 0)
    {
      await connection.rollback();
      connection.release();
      return res.status(400).json({message: "userdata silinirken hata olustu, islem geri alindi."});
    }

    const [res2] = await connection.promise().query(query2,[id]);
    if(res2.affectedRows === 0)
    {
      await connection.rollback();
      connection.release();
      return res.status(400).json({message: "users silinirken hata olustu, islem geri alindi."});
    }
    await connection.commit();
    connection.release();
    return res.status(201).json({message: "Bilgiler basariyla silindi."});
  }
  catch(err) {
    await connection.rollback();
    return res.status(500).json({error: "Veritabani hatasi."});
  }
});


app.use((req, res) => {
  res.status(404).json({message: "Bu API bulunmuyor."})
});