const express = require("express");
const connectDB = require("./config/db");


const app = express();


//connect database
connectDB();

//Middleware
app.use(express.json());

app.get("/test",(req,res)=>res.send("Hello World!!"))

app.use("/",require("./routes/auth"))



const PORT = 5000
app.listen(PORT,()=>console.log(`Server running on port ${PORT}`))