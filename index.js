const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const { connectToDB } = require("./db/db.connect");
const User = require("./models/user.model");
const Post = require("./models/post.model");
const Comment = require("./models/comment.model");

const app = express();
const PORT = process.env.PORT || 3002;

app.use(express.json());
app.use(
  cors({
    origin: [
      "https://playground-054-frontend.vercel.app",
      "http://localhost:5174",
    ],
    credentials: true,
    optionsSuccessStatus: 200,
  })
);
app.use(cookieParser());

connectToDB();

app.get("/", (req, res) => {
  res.json("Postify! Post your heart out");
});

app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});
