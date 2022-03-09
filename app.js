const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const os = require("os");
const hostname = os.hostname();
const hostnameNetwork = os.networkInterfaces();


require("dotenv").config();
const PORT = 5000;

const authRoutes = require("./routes/users");

const BASE_URL = "/api/v1"

console.log('BASE_HOST: ', process.env.BASE_HOST);
console.log('hostname: ', process.env.BASE_HOST);
console.log('hostnameNetwork: ', process.env.BASE_HOST);

mongoose
    .connect(process.env.MONGO_URI, {
        dbName: process.env.DB_NAME,
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => {
        console.log("Database connection Success.");
    })
    .catch((err) => {
        console.log("MONGO_URI: ",process.env.MONGO_URI);
        console.log("DB_NAME: ",process.env.DB_NAME);
        console.error("Mongo Connection Error", err);
    });

const app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/ping", (req, res) => {
    return res.send({
        error: false,
        message: "Server is healthy",
    });
});

app.use( BASE_URL + "/users", authRoutes);

app.listen(PORT, () => {
    console.log("Server started listening on PORT : " + PORT);
});
