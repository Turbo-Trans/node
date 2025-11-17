const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require("jsonwebtoken");
const app = express();
var path = require("path");
const bcrypt = require("bcrypt");
const con = require("./components/db");
const auth = require('./components/auth');


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
      SELECT u.userID, u.username, u.password, ud.email, ud.tel, ud.cityID, ud.address, ud.job, ud.warehouseID
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
      { userID: user.userID, username: user.username },
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

app.get('/getUsers', auth, async(req,res) => {
  const query = `select * from userData`;
  const [results] = await con.promise().query(query);
  res.json(results);
});


app.use((req, res) => {
  res.status(404).json({message: "Bu API bulunmuyor."})
});