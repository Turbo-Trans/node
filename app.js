const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require("jsonwebtoken");
const app = express();
var path = require("path");
const con = require("./components/db");


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


app.use((req, res) => {
  res.status(404).json({message: "Bu API bulunmuyor."})
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Node sunucusu ${PORT} portunda baslatildi.`);
});