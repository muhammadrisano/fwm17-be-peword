require("dotenv").config();
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const createError = require("http-errors");
const routes = require("./src/routes");
const cookieParser = require("cookie-parser");

const app = express();
const PORT = process.env.PORT || 5000;
// const corsOrigin = 
// [
//   "http://localhost:3000",
//   "http://localhost:5173",
//   "https://fe-blanja-team.vercel.app",
//   "https://peworld-putrapr.vercel.app",
//   "https://peworld-zeta.vercel.app",
//   "https://fwm17-sample-next.vercel.app",
//   "https://fe-peworld-three.vercel.app",
//   "https://peworld-next-js-xi.vercel.app",
//   "https://peworld-app-kappa.vercel.app",
//   "https://dimas-peworld.vercel.app",
//   "https://peworld-hirejob.vercel.app",
//   "https://peword-ags.netlify.app",
//   "https://wafash-peworld-react.netlify.app",
//   "https://peworlds-project.netlify.app",
//   "https://peworlds-project.netlify.app",
//   "https://crud-react-tailwind-o7f0z12yq-nizuma666s-projects.vercel.app",
//   "https://crud-react-tailwind-roan.vercel.app",
//   "https://mama-recipe-food.vercel.app"
// ]
const corsOrigin = function (origin, callback) {
  callback(null, true)
}

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
  cors({
    credentials: true,
    origin: corsOrigin,
  })
);
app.use(morgan("dev"));

app.use("/v1", routes);


app.get('/', (req, res, next)=>{
  res.json({
    message: 'API for peword is working'
  })
})

app.all("*", (req, res, next) => {
  next(new createError.NotFound());
});

app.use((err, req, res, next) => {
  const messError = err.message || "Internal Server Error";
  const statusCode = err.status || 500;

  res.status(statusCode).json({
    message: messError,
  });
});

app.listen(PORT, () => {
  console.log(`Server starting on port ${PORT}`);
});
